package plugins

import (
    "context"
    "os"
    "regexp"
    "strings"

    "github.com/xab-mack/smartscanner/internal/analysis"
    "github.com/xab-mack/smartscanner/internal/model"
    "github.com/xab-mack/smartscanner/internal/util"
)

// solidityTxOrigin flags use of tx.origin in authorization-sensitive checks
type solidityTxOrigin struct{}

func (d *solidityTxOrigin) Meta() model.RuleMeta {
    return model.RuleMeta{ID: "SOL-TX-ORIGIN", Title: "tx.origin used for authorization", Severity: model.SeverityHigh}
}

func (d *solidityTxOrigin) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
    return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityTxOrigin) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
    var findings []model.Finding
    pc, _ := pctx.(*analysis.ProjectContext)
    if pc == nil {
        return findings, nil
    }
    reHeader := regexp.MustCompile(`(?m)function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?[^\{]*\{`)
    for _, file := range pc.SolidityFiles {
        content := pc.FileContents[file]
        if content == "" { b, _ := os.ReadFile(file); content = string(b) }
        lc := strings.ToLower(content)
        if !strings.Contains(lc, "tx.origin") {
            continue
        }
        matches := reHeader.FindAllStringIndex(content, -1)
        for i, m := range matches {
            header := content[m[0]:m[1]]
            body := content[m[1]:]
            if i+1 < len(matches) { body = content[m[1]:matches[i+1][0]] }
            if !strings.Contains(strings.ToLower(body), "tx.origin") {
                continue
            }
            // flag if tx.origin appears near require/assert/if condition
            risk := false
            lines := strings.Split(body, "\n")
            for _, l := range lines {
                low := strings.ToLower(l)
                if strings.Contains(low, "tx.origin") && (strings.Contains(low, "require(") || strings.Contains(low, "assert(") || strings.Contains(low, "if (")) {
                    risk = true
                    break
                }
            }
            if !risk { continue }
            s, e := util.FindLineRange(content, header)
            findings = append(findings, model.Finding{
                RuleID:     d.Meta().ID,
                Severity:   model.SeverityHigh,
                Confidence: 0.85,
                DetectorID: "solidity-tx-origin",
                File:       file,
                StartLine:  s,
                EndLine:    e,
                Snippet:    util.ExtractSnippet(content, s, e, 8),
                Message:    "tx.origin used in authorization logic",
                Rationale:  "tx.origin is susceptible to phishing through smart contract calls; use msg.sender instead.",
                Remediation: "Replace tx.origin with msg.sender and implement proper access control.",
                References: []string{"SWC-115"},
                Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, header),
            })
        }
    }
    return findings, nil
}


