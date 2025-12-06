package caddywaf

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// DebugRequest logs detailed information about a request for debugging
func (m *Middleware) DebugRequest(r *http.Request, state *WAFState, msg string) {
	if m.LogSeverity != "debug" {
		return
	}

	var ruleIDs []string
	var scores []string

	// Log all matched rules and their scores
	m.ruleHits.Range(func(key, value interface{}) bool {
		ruleID, ok := key.(RuleID)
		if !ok {
			return true
		}
		atomicCounter, ok := value.(*atomic.Int64)
		if !ok {
			return true
		}
		hitCount := atomicCounter.Load()
		ruleIDs = append(ruleIDs, string(ruleID))
		scores = append(scores, fmt.Sprintf("%s:%d", string(ruleID), hitCount))
		return true
	})

	// Create a detailed debug log
	m.logger.Debug(fmt.Sprintf("WAF DEBUG: %s", msg),
		zap.String("timestamp", time.Now().Format(time.RFC3339)),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("query", r.URL.RawQuery),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
		zap.Bool("blocked", state.Blocked),
		zap.Int("status_code", state.StatusCode),
		zap.Bool("response_written", state.ResponseWritten),
		zap.String("matched_rules", strings.Join(ruleIDs, ",")),
		zap.String("rule_scores", strings.Join(scores, ",")),
	)
}

// DumpRulesToFile dumps the loaded rules to a file for inspection
func (m *Middleware) DumpRulesToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString("=== WAF Rules Dump ===\n\n"); err != nil {
		return err
	}

	for phase := 1; phase <= 4; phase++ {
		fmt.Fprintf(f, "== Phase %d Rules ==\n", phase)
		rules, ok := m.Rules[phase]
		if !ok || len(rules) == 0 {
			if _, err := f.WriteString("		No rules for this phase\n\n"); err != nil {
				return err
			}
			continue
		}

		for i, rule := range rules {
			fmt.Fprintf(f, "		Rule %d:\n", i+1)
			fmt.Fprintf(f, "		ID: %s\n", rule.ID)
			fmt.Fprintf(f, "		Pattern: %s\n", rule.Pattern)
			fmt.Fprintf(f, "    Targets: %v\n", rule.Targets)
			fmt.Fprintf(f, "    Score: %d\n", rule.Score)
			fmt.Fprintf(f, "    Action: %s\n", rule.Action)
			fmt.Fprintf(f, "    Description: %s\n", rule.Description)
			if _, err := f.WriteString("\n"); err != nil {
				return err
			}
		}
	}

	return nil
}
