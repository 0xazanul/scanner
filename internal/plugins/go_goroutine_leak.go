package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goGoroutineLeak flags goroutines writing to channels without select/timeouts (heuristic)
type goGoroutineLeak struct{}

func (d *goGoroutineLeak) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-GOROUTINE-LEAK", Title: "Potential goroutine leak via unbounded channel ops", Severity: model.SeverityMedium}
}

func (d *goGoroutineLeak) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goGoroutineLeak) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		if strings.Contains(content, "go ") && strings.Contains(content, "make(chan") {
			hasSelect := strings.Contains(content, "select {")
			if !hasSelect {
				s, e := util.FindLineRange(content, "go ")
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityMedium,
					Confidence:  0.45,
					DetectorID:  "go-goroutine-leak",
					File:        file,
					StartLine:   s,
					EndLine:     e,
					Snippet:     util.ExtractSnippet(content, s, e, 6),
					Message:     "Goroutine with channel ops may lack select/timeout",
					Rationale:   "Unbounded goroutines and blocking channel ops can leak resources.",
					Remediation: "Use context cancellation or select with timeout and ensure consumers exist.",
				})
			}
		}
	}
	return findings, nil
}
