package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goWeakCipherMode flags AES-CBC usage without authentication
type goWeakCipherMode struct{}

func (d *goWeakCipherMode) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-WEAK-CIPHER", Title: "AES-CBC used without authentication", Severity: model.SeverityHigh}
}

func (d *goWeakCipherMode) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goWeakCipherMode) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
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
		if strings.Contains(l, "newcbcencrypter") || strings.Contains(l, "newcbcdecrypter") {
			// lower confidence unless hmac/aead nearby
			if !(strings.Contains(l, "hmac") || strings.Contains(l, "gcm") || strings.Contains(l, "aead")) {
				s, e := util.FindLineRange(content, "CBC")
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityHigh,
					Confidence:  0.5,
					DetectorID:  "go-weak-cipher",
					File:        file,
					StartLine:   s,
					EndLine:     e,
					Snippet:     util.ExtractSnippet(content, s, e, 6),
					Message:     "AES-CBC used without authentication",
					Rationale:   "CBC is malleable; use AEAD (GCM/ChaCha20-Poly1305) or add HMAC.",
					Remediation: "Switch to AEAD cipher modes (cipher.NewGCM) or add HMAC over ciphertext.",
				})
			}
		}
	}
	return findings, nil
}
