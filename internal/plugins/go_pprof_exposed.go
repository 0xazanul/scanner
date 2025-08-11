package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goPprofExposed flags pprof imports or servers bound to 0.0.0.0 in non-dev code
type goPprofExposed struct{}

func (d *goPprofExposed) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-PPROF-EXPOSED", Title: "Debug/pprof endpoints exposed in production", Severity: model.SeverityMedium}
}

func (d *goPprofExposed) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goPprofExposed) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		l := strings.ToLower(content)
		if strings.Contains(l, "net/http/pprof") || strings.Contains(l, "pprof.") {
			s, e := util.FindLineRange(content, "pprof")
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityMedium,
				Confidence:  0.5,
				DetectorID:  "go-pprof-exposed",
				File:        file,
				StartLine:   s,
				EndLine:     e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "Debug/pprof possibly exposed",
				Rationale:   "Exposed debug endpoints can leak internals and be abused.",
				Remediation: "Guard with environment checks or disable in production builds.",
			})
		}
		if strings.Contains(l, ":0.0.0.0:") || strings.Contains(l, "0.0.0.0:") {
			s, e := util.FindLineRange(content, "0.0.0.0:")
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityMedium,
				Confidence:  0.5,
				DetectorID:  "go-pprof-exposed",
				File:        file,
				StartLine:   s,
				EndLine:     e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "HTTP server bound to 0.0.0.0",
				Rationale:   "Binding to all interfaces may unintentionally expose debug endpoints.",
				Remediation: "Bind to localhost or protect with auth and firewalls.",
			})
		}
	}
	return findings, nil
}
