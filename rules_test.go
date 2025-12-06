package caddywaf

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go.uber.org/zap"
)

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name:    "Empty ID",
			rule:    Rule{},
			wantErr: true,
		},
		{
			name: "Empty Pattern",
			rule: Rule{
				ID: "test",
			},
			wantErr: true,
		},
		{
			name: "No Targets",
			rule: Rule{
				ID:      "test",
				Pattern: ".*",
			},
			wantErr: true,
		},
		{
			name: "Invalid Phase",
			rule: Rule{
				ID:      "test",
				Pattern: ".*",
				Targets: []string{"REQUEST_URI"},
				Phase:   0,
			},
			wantErr: true,
		},
		{
			name: "Negative Score",
			rule: Rule{
				ID:      "test",
				Pattern: ".*",
				Targets: []string{"REQUEST_URI"},
				Phase:   1,
				Score:   -1,
			},
			wantErr: true,
		},
		{
			name: "Invalid Action",
			rule: Rule{
				ID:      "test",
				Pattern: ".*",
				Targets: []string{"REQUEST_URI"},
				Phase:   1,
				Score:   5,
				Action:  "invalid",
			},
			wantErr: true,
		},
		{
			name: "Valid Rule",
			rule: Rule{
				ID:      "test",
				Pattern: ".*",
				Targets: []string{"REQUEST_URI"},
				Phase:   1,
				Score:   5,
				Action:  "block",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRule(&tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProcessRuleMatch(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name             string
		rule             Rule
		anomalyScore     int
		anomalyThreshold int
		responseWritten  bool
		wantBlock        bool
	}{
		{
			name: "Block Action Rule",
			rule: Rule{
				ID:     "test1",
				Action: "block",
				Score:  5,
			},
			anomalyScore:     0,
			anomalyThreshold: 10,
			responseWritten:  false,
			wantBlock:        true,
		},
		{
			name: "Score Exceeds Threshold",
			rule: Rule{
				ID:     "test2",
				Action: "log",
				Score:  15,
			},
			anomalyScore:     0,
			anomalyThreshold: 10,
			responseWritten:  false,
			wantBlock:        true,
		},
		{
			name: "Response Already Written",
			rule: Rule{
				ID:     "test3",
				Action: "block",
				Score:  5,
			},
			anomalyScore:     0,
			anomalyThreshold: 10,
			responseWritten:  true,
			wantBlock:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Middleware{
				logger:                logger,
				AnomalyThreshold:      tt.anomalyThreshold,
				ruleHits:              sync.Map{},
				muMetrics:             sync.RWMutex{},
				requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/test", nil)
			ctx := context.WithValue(r.Context(), ContextKeyLogId("logID"), "test-log-id")
			r = r.WithContext(ctx)

			state := &WAFState{
				TotalScore:      tt.anomalyScore,
				ResponseWritten: tt.responseWritten,
			}

			result := m.processRuleMatch(w, r, &tt.rule, "ARGS", "test-value", state)
			if result == tt.wantBlock {
				t.Errorf("processRuleMatch() returned %v, want %v", result, !tt.wantBlock)
			}
		})
	}
}

func TestLoadRules(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create temp test files
	tmpDir := t.TempDir()

	validRuleFile := filepath.Join(tmpDir, "valid_rules.json")
	validRules := `[
		{
			"id": "test1",
			"pattern": ".*",
			"targets": ["REQUEST_URI"],
			"phase": 1,
			"score": 5,
			"action": "block"
		}
	]`
	os.WriteFile(validRuleFile, []byte(validRules), 0o644)

	invalidRuleFile := filepath.Join(tmpDir, "invalid_rules.json")
	invalidRules := `[
		{
			"id": "",
			"pattern": "",
			"targets": [],
			"phase": 0,
			"score": -1
		}
	]`
	os.WriteFile(invalidRuleFile, []byte(invalidRules), 0o644)

	tests := []struct {
		name    string
		paths   []string
		wantErr bool
	}{
		{
			name:    "Valid Rules File",
			paths:   []string{validRuleFile},
			wantErr: false,
		},
		{
			name:    "Invalid Rules File",
			paths:   []string{invalidRuleFile},
			wantErr: true,
		},
		{
			name:    "No Rules Files",
			paths:   []string{},
			wantErr: false,
		},
		{
			name:    "Non-existent File",
			paths:   []string{"nonexistent.json"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Middleware{
				logger:    logger,
				mu:        sync.RWMutex{},
				ruleCache: NewRuleCache(),
			}

			err := m.loadRules(tt.paths)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
