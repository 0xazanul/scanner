package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

type solidityHeuristics struct{}

func (s *solidityHeuristics) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-BASE-000", Title: "Solidity heuristic checks", Severity: model.SeverityLow}
}

func (s *solidityHeuristics) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	_ = filepath.WalkDir(req.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".sol") {
			return nil
		}
		// Minimal heuristic: flag usage of tx.origin or selfdestruct as examples
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		if strings.Contains(content, "tx.origin") {
			s, e := util.FindLineRange(content, "tx.origin")
			findings = append(findings, model.Finding{
				RuleID:     "SOL-TX-ORIGIN",
				Severity:   model.SeverityHigh,
				Confidence: 0.8,
				DetectorID: "solidity-heuristics",
				File:       path, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 8),
				Message:     "Use of tx.origin for authorization is dangerous",
				Rationale:   "tx.origin can be phished via intermediate contracts",
				Remediation: "Use msg.sender and proper access control modifiers instead of tx.origin.",
				References:  []string{"SWC-115"},
				Fingerprint: util.Fingerprint("SOL-TX-ORIGIN", path, s, e, "tx.origin"),
			})
		}
		cl := strings.ToLower(content)
		if strings.Contains(cl, "selfdestruct(") || strings.Contains(cl, "suicide(") {
			s, e := util.FindLineRange(cl, "selfdestruct(")
			findings = append(findings, model.Finding{
				RuleID:     "SOL-SELFDESTRUCT",
				Severity:   model.SeverityHigh,
				Confidence: 0.7,
				DetectorID: "solidity-heuristics",
				File:       path, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 8),
				Message:     "Use of selfdestruct detected",
				Rationale:   "Selfdestruct can brick contracts and reroute ether",
				References:  []string{"SWC-106"},
				Fingerprint: util.Fingerprint("SOL-SELFDESTRUCT", path, s, e, "selfdestruct"),
			})
		}
		return nil
	})
	return findings, nil
}
