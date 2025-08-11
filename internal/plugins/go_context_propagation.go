package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goContextPropagation flags handlers missing context propagation to downstream calls
type goContextPropagation struct{}

func (d *goContextPropagation) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-CONTEXT-PROP", Title: "Missing context propagation in handlers", Severity: model.SeverityMedium}
}

func (d *goContextPropagation) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goContextPropagation) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		// naive: presence of http handler signature but DB/HTTP calls without ctx
		if strings.Contains(content, "func(") && (strings.Contains(content, "http.ResponseWriter") && strings.Contains(content, "*http.Request")) {
			hasCtx := strings.Contains(content, ".WithContext(") || strings.Contains(content, "req.Context()")
			if !hasCtx && (strings.Contains(content, ".Do(") || strings.Contains(content, ".Exec(") || strings.Contains(content, ".Query(")) {
				s, e := util.FindLineRange(content, "*http.Request")
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityMedium,
					Confidence:  0.5,
					DetectorID:  "go-context-prop",
					File:        file,
					StartLine:   s,
					EndLine:     e,
					Snippet:     util.ExtractSnippet(content, s, e, 6),
					Message:     "Handler performs external operations without propagating request context",
					Rationale:   "Lack of context breaks cancellation/timeouts for downstream operations.",
					Remediation: "Use ctx := req.Context() and pass it into DB/HTTP calls (ExecContext/Do with context).",
				})
			}
		}
	}
	return findings, nil
}
