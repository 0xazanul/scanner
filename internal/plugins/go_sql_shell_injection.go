package plugins

import (
    "context"
    "regexp"
    "strings"

    "github.com/xab-mack/smartscanner/internal/analysis"
    "github.com/xab-mack/smartscanner/internal/model"
    "github.com/xab-mack/smartscanner/internal/util"
)

// goSQLShellInjection flags string composition with user-like inputs passed to db.Exec/exec.Command
type goSQLShellInjection struct{}

func (d *goSQLShellInjection) Meta() model.RuleMeta {
    return model.RuleMeta{ID: "GO-INJECTION", Title: "Potential SQL/shell injection via string composition", Severity: model.SeverityCritical}
}

func (d *goSQLShellInjection) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
    return d.AnalyzeV2(ctx, nil, req)
}

func (d *goSQLShellInjection) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
    var findings []model.Finding
    pc, _ := pctx.(*analysis.ProjectContext)
    if pc == nil { return findings, nil }
    reSink := regexp.MustCompile(`(?m)\.(Exec|Query|QueryRow)\s*\(`)
    reCmd := regexp.MustCompile(`(?m)exec\.Command\s*\(`)
    reConcat := regexp.MustCompile(`\+\s*\w`)
    for file, content := range pc.FileContents {
        if !strings.HasSuffix(strings.ToLower(file), ".go") { continue }
        lines := strings.Split(content, "\n")
        for i, l := range lines {
            low := strings.ToLower(l)
            // SQL sinks
            if reSink.MatchString(l) {
                // suspicious if using fmt.Sprintf or string concatenation
                suspicious := strings.Contains(l, "fmt.Sprintf(") || reConcat.MatchString(l)
                // stronger if same or previous lines reference http request input
                if i > 0 {
                    pl := strings.ToLower(lines[i-1])
                    if strings.Contains(pl, "req.") || strings.Contains(pl, "r.") || strings.Contains(pl, "query(") || strings.Contains(pl, "form") {
                        suspicious = true
                    }
                }
                if suspicious {
                    s := i + 1
                    findings = append(findings, model.Finding{
                        RuleID:     d.Meta().ID,
                        Severity:   model.SeverityCritical,
                        Confidence: 0.5,
                        DetectorID: "go-injection",
                        File:       file,
                        StartLine:  s,
                        EndLine:    s,
                        Snippet:    util.ExtractSnippet(content, s, s, 6),
                        Message:    "Dynamic SQL construction may allow injection; use parameterized queries",
                        Rationale:  "Concatenating user input into SQL can be exploited to execute arbitrary statements.",
                        Remediation: "Use placeholders and parameter binding (db.ExecContext(ctx, query, args...)).",
                    })
                }
            }
            // Shell sinks
            if reCmd.MatchString(l) {
                suspicious := strings.Contains(l, "fmt.Sprintf(") || reConcat.MatchString(l)
                if i > 0 {
                    pl := strings.ToLower(lines[i-1])
                    if strings.Contains(pl, "req.") || strings.Contains(pl, "r.") || strings.Contains(pl, "query(") || strings.Contains(pl, "form") {
                        suspicious = true
                    }
                }
                if suspicious {
                    s := i + 1
                    findings = append(findings, model.Finding{
                        RuleID:     d.Meta().ID,
                        Severity:   model.SeverityCritical,
                        Confidence: 0.5,
                        DetectorID: "go-injection",
                        File:       file,
                        StartLine:  s,
                        EndLine:    s,
                        Snippet:    util.ExtractSnippet(content, s, s, 6),
                        Message:    "Command constructed dynamically from input; risk of shell injection",
                        Rationale:  "Passing untrusted data to exec.Command without proper argument separation can be abused.",
                        Remediation: "Avoid shells; pass each argument separately and validate/allowlist inputs.",
                    })
                }
            }
            _ = low
        }
    }
    return findings, nil
}


