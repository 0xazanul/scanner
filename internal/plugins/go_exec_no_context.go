package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goExecNoContext flags exec.Command usage without CommandContext
type goExecNoContext struct{}

func (d *goExecNoContext) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-EXEC-NO-CONTEXT", Title: "exec.Command used without context/timeout", Severity: model.SeverityMedium}
}

func (d *goExecNoContext) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goExecNoContext) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		if !strings.Contains(content, "exec.Command(") {
			continue
		}
		if strings.Contains(content, "exec.CommandContext(") {
			continue
		}
		s, e := util.FindLineRange(content, "exec.Command(")
		findings = append(findings, model.Finding{
			RuleID:      d.Meta().ID,
			Severity:    model.SeverityMedium,
			Confidence:  0.7,
			DetectorID:  "go-exec-no-context",
			File:        file,
			StartLine:   s,
			EndLine:     e,
			Snippet:     util.ExtractSnippet(content, s, e, 6),
			Message:     "exec.Command used without context; process may hang",
			Rationale:   "Using exec without context/timeout risks indefinite blocking and resource leaks.",
			Remediation: "Use exec.CommandContext with a context that has a timeout or deadline.",
		})
	}
	return findings, nil
}
