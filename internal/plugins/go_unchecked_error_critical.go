package plugins

import (
	"context"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goUncheckedErrorCritical flags ignored errors from critical APIs (DB exec, HTTP Do, Fabric PutState)
type goUncheckedErrorCritical struct{}

func (d *goUncheckedErrorCritical) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-UNCHECKED-ERROR", Title: "Unchecked error from critical call", Severity: model.SeverityHigh}
}

func (d *goUncheckedErrorCritical) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goUncheckedErrorCritical) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	// heuristics over source lines
	reCritical := regexp.MustCompile(`\b(DB|db|sql|http|client|stub)\b`)
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		lines := strings.Split(content, "\n")
		for i := 0; i < len(lines); i++ {
			l := lines[i]
			if !reCritical.MatchString(l) {
				continue
			}
			// common critical calls
			if strings.Contains(l, ".Exec(") || strings.Contains(l, ".Do(") || strings.Contains(l, "PutState(") || strings.Contains(l, ".Write(") {
				// very rough: if next lines lack 'err' checks, report
				checked := false
				lookahead := 3
				for j := 0; j < lookahead && i+j < len(lines); j++ {
					low := strings.ToLower(lines[i+j])
					if strings.Contains(low, "if err != nil") || strings.Contains(low, "require.noerror") || strings.Contains(low, "assert.noerror") {
						checked = true
						break
					}
				}
				if !checked {
					start := i + 1
					findings = append(findings, model.Finding{
						RuleID:      d.Meta().ID,
						Severity:    model.SeverityHigh,
						Confidence:  0.5,
						DetectorID:  "go-unchecked-error-critical",
						File:        file,
						StartLine:   start,
						EndLine:     start,
						Snippet:     util.ExtractSnippet(content, start, start, 6),
						Message:     "Critical call without subsequent error handling",
						Rationale:   "Ignoring errors from DB/HTTP/Fabric calls can lead to inconsistent state or security issues.",
						Remediation: "Capture and check errors; abort or compensate on failure.",
					})
				}
			}
		}
	}
	return findings, nil
}
