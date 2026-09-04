package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// Rules-audit part 4: a rule with action "log" must not push a request over
// the anomaly threshold on its own (or in aggregate) by default. Its score is
// tracked as advisory. Setting LogScoresBlock restores legacy accumulation.

func logScoreMW(t *testing.T, logScoresBlock bool) *Middleware {
	t.Helper()
	return &Middleware{
		logger:                zap.NewNop(),
		AnomalyThreshold:      5,
		LogScoresBlock:        logScoresBlock,
		ruleHitsByPhase:       map[int]int64{},
		requestValueExtractor: NewRequestValueExtractor(zap.NewNop(), false, 0),
		blockedByReason:       map[string]int64{},
		topIPsBlocked:         map[string]int64{},
		geoIPStats:            map[string]int64{},
	}
}

func TestLogRulesDoNotBlockByDefault(t *testing.T) {
	m := logScoreMW(t, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	state := m.initializeWAFState()

	// Three log rules, each score 3 -> 9 total, well over the threshold of 5.
	for i := 0; i < 3; i++ {
		logRule := &Rule{ID: "log-rule", Action: "log", Score: 3, Phase: 1}
		cont := m.processRuleMatch(rec, req, logRule, "ARGS", "v", state)
		assert.True(t, cont, "log rule must not stop processing")
	}
	assert.False(t, state.Blocked, "accumulated log score must not block by default")
	assert.Equal(t, 0, state.TotalScore, "log scores must not enter the blocking score")
	assert.Equal(t, 9, state.AdvisoryScore, "log scores must be tracked as advisory")
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

func TestLogRulesBlockWhenConfigured(t *testing.T) {
	m := logScoreMW(t, true)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	state := m.initializeWAFState()

	blocked := false
	for i := 0; i < 3; i++ {
		logRule := &Rule{ID: "log-rule", Action: "log", Score: 3, Phase: 1}
		if !m.processRuleMatch(rec, req, logRule, "ARGS", "v", state) {
			blocked = true
			break
		}
	}
	assert.True(t, blocked, "with log_scores_block, accumulated log score must block")
	assert.True(t, state.Blocked)
	assert.GreaterOrEqual(t, state.TotalScore, m.AnomalyThreshold)
}

func TestLowScoreBlockRuleStillBlocksImmediately(t *testing.T) {
	// action "block" blocks on the first match regardless of score, so a
	// block rule scored below the threshold must still block. This is what
	// makes moving log rules out of the blocking score safe: real detections
	// use action "block" and do not depend on threshold accumulation.
	m := logScoreMW(t, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	state := m.initializeWAFState()

	r := &Rule{ID: "b", Action: "block", Score: 1, Phase: 1}
	assert.False(t, m.processRuleMatch(rec, req, r, "ARGS", "v", state), "block action must block on first match")
	assert.True(t, state.Blocked)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestSingleHighScoreBlockRuleStillBlocks(t *testing.T) {
	m := logScoreMW(t, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	state := m.initializeWAFState()

	r := &Rule{ID: "b", Action: "block", Score: 9, Phase: 1}
	assert.False(t, m.processRuleMatch(rec, req, r, "ARGS", "v", state))
	assert.True(t, state.Blocked)
}

// TestRuleActionUnmarshalsFromJSON pins the fix for the json:"mode" tag bug:
// the shipped rule files key the action as "action", so a rule loaded from
// JSON must have Action populated. Before the fix every rule unmarshalled to
// Action=="" — action:"block" never triggered an explicit block, and the
// log-vs-block distinction the advisory scoring relies on did not exist. This
// test loads real rules and asserts both actions are present, so the tag can
// never silently regress.
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
