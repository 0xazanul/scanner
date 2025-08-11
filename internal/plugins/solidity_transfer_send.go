package plugins

import (
    "context"
    "os"
    "strings"

    "github.com/xab-mack/smartscanner/internal/analysis"
    "github.com/xab-mack/smartscanner/internal/model"
    "github.com/xab-mack/smartscanner/internal/util"
)

// solidityTransferSend flags usage of transfer/send which rely on 2300 gas stipend
type solidityTransferSend struct{}

func (d *solidityTransferSend) Meta() model.RuleMeta {
    return model.RuleMeta{ID: "SOL-TRANSFER-SEND", Title: "Use of transfer/send (gas stipend)", Severity: model.SeverityMedium}
}

func (d *solidityTransferSend) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
    return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityTransferSend) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
    var findings []model.Finding
    pc, _ := pctx.(*analysis.ProjectContext)
    if pc == nil { return findings, nil }
    for _, file := range pc.SolidityFiles {
        content := pc.FileContents[file]
        if content == "" { b, _ := os.ReadFile(file); content = string(b) }
        lc := strings.ToLower(content)
        for _, needle := range []string{".transfer(", ".send("} {
            if !strings.Contains(lc, needle) { continue }
            s, e := util.FindLineRange(lc, needle)
            findings = append(findings, model.Finding{
                RuleID:     d.Meta().ID,
                Severity:   model.SeverityMedium,
                Confidence: 0.7,
                DetectorID: "solidity-transfer-send",
                File:       file,
                StartLine:  s,
                EndLine:    e,
                Snippet:    util.ExtractSnippet(content, s, e, 6),
                Message:    "Use of transfer/send can break with gas repricing",
                Rationale:  "transfer/send forward 2300 gas and may revert; call{value:..} with checks is preferred.",
                Remediation: "Use call{value: amount}("") and handle the success boolean, or implement pull payment pattern.",
                References: []string{"EIP-1884"},
                Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, needle),
            })
        }
    }
    return findings, nil
}


