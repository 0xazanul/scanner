package plugins

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// solidityFloatingPragma detects caret or open ranges without pinning minor version (SWC-103)
type solidityFloatingPragma struct{}

func (d *solidityFloatingPragma) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-FLOATING-PRAGMA", Title: "Floating pragma solidity version", Severity: model.SeverityMedium}
}

func (d *solidityFloatingPragma) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityFloatingPragma) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	rePragma := regexp.MustCompile(`(?m)^\s*pragma\s+solidity\s+([^;]+);`)
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		m := rePragma.FindStringSubmatch(content)
		if len(m) < 2 {
			continue
		}
		ver := strings.TrimSpace(m[1])
		floating := strings.Contains(ver, "^") || strings.Contains(ver, ">=") || strings.Contains(ver, "<")
		// Accept exact pins like 0.8.20 or =0.8.20
		exact := regexp.MustCompile(`^=?\s*\d+\.\d+\.\d+$`).MatchString(ver)
		if floating && !exact {
			s, e := util.FindLineRange(content, m[0])
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityMedium,
				Confidence:  0.9,
				DetectorID:  "solidity-floating-pragma",
				File:        file,
				StartLine:   s,
				EndLine:     e,
				Snippet:     util.ExtractSnippet(content, s, e, 3),
				Message:     "Floating pragma solidity version",
				Rationale:   "Using version ranges can yield different compiler behavior across builds.",
				Remediation: "Pin to an exact compiler version, e.g., pragma solidity 0.8.20; and enforce in CI.",
				References:  []string{"SWC-103"},
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, ver),
			})
		}
	}
	return findings, nil
}
