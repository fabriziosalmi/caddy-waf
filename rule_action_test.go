package caddywaf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestRuleActionUnmarshalsFromJSON pins the fix for the json:"mode" tag bug:
// the shipped rule files key the action as "action", so a rule loaded from
// JSON must have Action populated. Before the fix every rule unmarshalled to
// Action=="" — action:"block" never triggered an explicit block, and the
// log-vs-block distinction did not exist at runtime. This test loads the real
// rules.json and asserts both actions are present, so the tag cannot silently
// regress. The Go tests did not catch the original bug because they set
// Action directly on the struct, bypassing JSON.
func TestRuleActionUnmarshalsFromJSON(t *testing.T) {
	m := &Middleware{
		logger:                zap.NewNop(),
		ruleCache:             NewRuleCache(),
		requestValueExtractor: NewRequestValueExtractor(zap.NewNop(), false, 0),
	}
	m.Rules = map[int][]Rule{}
	if err := m.loadRules([]string{"rules.json"}); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	var haveBlock, haveLog bool
	for _, phaseRules := range m.Rules {
		for _, r := range phaseRules {
			switch r.Action {
			case "block":
				haveBlock = true
			case "log":
				haveLog = true
			case "":
				t.Errorf("rule %q loaded with empty Action (json tag regression?)", r.ID)
			}
		}
	}
	assert.True(t, haveBlock, "rules.json must contain at least one block-action rule")
	assert.True(t, haveLog, "rules.json must contain at least one log-action rule")
}

// TestRuleModeKeyStillAccepted pins the compatibility alias: rule files written
// against the earlier documentation used "mode", and they must keep working.
// "action" wins when both keys are present.
func TestRuleModeKeyStillAccepted(t *testing.T) {
	var rules []Rule
	src := `[
	  {"id":"legacy","phase":1,"pattern":"x","targets":["ARGS"],"score":1,"mode":"block"},
	  {"id":"canonical","phase":1,"pattern":"x","targets":["ARGS"],"score":1,"action":"log"},
	  {"id":"both","phase":1,"pattern":"x","targets":["ARGS"],"score":1,"action":"log","mode":"block"},
	  {"id":"neither","phase":1,"pattern":"x","targets":["ARGS"],"score":1}
	]`
	if err := json.Unmarshal([]byte(src), &rules); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rules {
		got[r.ID] = r.Action
	}
	assert.Equal(t, "block", got["legacy"], `"mode" must still populate Action`)
	assert.Equal(t, "log", got["canonical"])
	assert.Equal(t, "log", got["both"], `"action" must win over "mode"`)
	assert.Equal(t, "", got["neither"])
}

// TestBlockActionFromJSONBlocksBelowThreshold pins the runtime effect of the
// tag fix end to end: a rule whose file says "action": "block" blocks on its
// first match even when its score is below anomaly_threshold. Before the fix
// this request passed, because Action was "" and blocking happened only once
// accumulated scores crossed the threshold.
func TestBlockActionFromJSONBlocksBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	rules := `[{"id":"explicit-block","phase":1,"pattern":"^probe$","targets":["HEADERS:X-Probe"],"severity":"LOW","action":"block","score":1,"description":""}]`
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := zap.NewNop()
	m := &Middleware{
		logger: logger, blacklistLoader: NewBlacklistLoader(logger),
		AnomalyThreshold: 20, ruleCache: NewRuleCache(), ipBlacklist: iptrie.NewTrie(),
		dnsBlacklist: map[string]struct{}{}, ruleHitsByPhase: map[int]int64{},
		RuleFiles:             []string{path},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		provisionTime:         time.Now(), topIPsBlocked: map[string]int64{},
		blockedByReason: map[string]int64{}, geoIPStats: map[string]int64{},
	}
	if err := m.loadRules(m.RuleFiles); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Probe", "probe")
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, r, next)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a block-action rule must block on match regardless of score")
}
