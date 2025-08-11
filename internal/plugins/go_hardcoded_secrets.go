package plugins

import (
	"context"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goHardcodedSecrets flags PEM-like or long hex constants likely to be secrets
type goHardcodedSecrets struct{}

func (d *goHardcodedSecrets) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-HARDCODED-SECRETS", Title: "Hardcoded secrets or private keys", Severity: model.SeverityCritical}
}

func (d *goHardcodedSecrets) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goHardcodedSecrets) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	rePEM := regexp.MustCompile(`-----BEGIN (RSA|EC|PRIVATE) KEY-----`)
	reHex := regexp.MustCompile(`(?i)\b[0-9a-f]{64,}\b`)
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		if rePEM.FindStringIndex(content) != nil || reHex.FindStringIndex(content) != nil {
			s, e := util.FindLineRange(content, "BEGIN ")
			if s == 0 {
				s, e = util.FindLineRange(content, "0")
			}
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityCritical,
				Confidence:  0.55,
				DetectorID:  "go-hardcoded-secrets",
				File:        file,
				StartLine:   s,
				EndLine:     e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "Potential hardcoded secret or private key",
				Rationale:   "Secret material should not be embedded in source code.",
				Remediation: "Move secrets to a secure secrets manager or environment variables and rotate keys.",
			})
		}
	}
	return findings, nil
}
