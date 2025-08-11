package plugins

import (
    "context"
    "strings"

    "github.com/xab-mack/smartscanner/internal/analysis"
    "github.com/xab-mack/smartscanner/internal/model"
    "github.com/xab-mack/smartscanner/internal/util"
)

// goCryptoRandMisuse flags math/rand used for keys/tokens
type goCryptoRandMisuse struct{}

func (d *goCryptoRandMisuse) Meta() model.RuleMeta {
    return model.RuleMeta{ID: "GO-CRYPTO-RAND-MISUSE", Title: "Insecure randomness for cryptographic purposes", Severity: model.SeverityHigh}
}

func (d *goCryptoRandMisuse) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
    return d.AnalyzeV2(ctx, nil, req)
}

func (d *goCryptoRandMisuse) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
    var findings []model.Finding
    pc, _ := pctx.(*analysis.ProjectContext)
    if pc == nil { return findings, nil }
    for file, content := range pc.FileContents {
        if !strings.HasSuffix(strings.ToLower(file), ".go") { continue }
        l := strings.ToLower(content)
        if strings.Contains(l, "math/rand") || strings.Contains(l, "rand.") {
            // stronger if same file mentions token/key/nonce
            if strings.Contains(l, "token") || strings.Contains(l, "secret") || strings.Contains(l, "nonce") || strings.Contains(l, "key") {
                s, e := util.FindLineRange(content, "rand.")
                findings = append(findings, model.Finding{
                    RuleID:     d.Meta().ID,
                    Severity:   model.SeverityHigh,
                    Confidence: 0.5,
                    DetectorID: "go-crypto-rand-misuse",
                    File:       file,
                    StartLine:  s,
                    EndLine:    e,
                    Snippet:    util.ExtractSnippet(content, s, e, 6),
                    Message:    "math/rand used for cryptographic randomness",
                    Rationale:  "math/rand is predictable and unsuitable for security-sensitive randomness.",
                    Remediation: "Use crypto/rand and appropriate encoding.",
                })
            }
        }
    }
    return findings, nil
}


