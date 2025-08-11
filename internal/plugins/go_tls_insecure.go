package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goTLSInsecure finds tls.Config with InsecureSkipVerify=true
type goTLSInsecure struct{}

func (d *goTLSInsecure) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-TLS-INSECURE", Title: "Insecure TLS configuration (InsecureSkipVerify)", Severity: model.SeverityHigh}
}

func (d *goTLSInsecure) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goTLSInsecure) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
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
		if strings.Contains(l, "insecureskipverify: true") {
			s, e := util.FindLineRange(content, "InsecureSkipVerify")
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityHigh,
				Confidence:  0.8,
				DetectorID:  "go-tls-insecure",
				File:        file,
				StartLine:   s,
				EndLine:     e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "tls.Config sets InsecureSkipVerify=true",
				Rationale:   "Disables certificate verification and enables MitM attacks.",
				Remediation: "Remove InsecureSkipVerify or properly configure trusted roots/pinning.",
			})
		}
	}
	return findings, nil
}
