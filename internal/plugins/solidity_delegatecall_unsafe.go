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

// solidityDelegatecallUnsafe flags delegatecall where target can be user-controlled
type solidityDelegatecallUnsafe struct{}

func (d *solidityDelegatecallUnsafe) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-UNSAFE-DELEGATECALL", Title: "delegatecall to potentially untrusted target", Severity: model.SeverityCritical}
}

func (d *solidityDelegatecallUnsafe) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityDelegatecallUnsafe) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}

	reHeader := regexp.MustCompile(`(?m)function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)?[^\{]*\{`)
	reDC := regexp.MustCompile(`(?i)\.delegatecall\s*\(([^)]+)\)`)

	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		lc := strings.ToLower(content)
		if !strings.Contains(lc, ".delegatecall(") {
			continue
		}
		matches := reHeader.FindAllStringIndex(content, -1)
		for i, m := range matches {
			header := content[m[0]:m[1]]
			body := content[m[1]:]
			if i+1 < len(matches) {
				body = content[m[1]:matches[i+1][0]]
			}
			// collect params and visibility
			parts := reHeader.FindStringSubmatch(header)
			params := []string{}
			if len(parts) >= 3 {
				rawParams := parts[2]
				for _, p := range strings.Split(rawParams, ",") {
					p = strings.TrimSpace(p)
					if p == "" {
						continue
					}
					toks := strings.Fields(p)
					if len(toks) > 0 {
						name := toks[len(toks)-1]
						if isIdentifier(name) {
							params = append(params, name)
						}
					}
				}
			}
			// scan delegatecall occurrences in body
			bl := strings.ToLower(body)
			locs := reDC.FindAllStringSubmatchIndex(bl, -1)
			for _, loc := range locs {
				full := body[loc[0]:loc[1]]
				arg := strings.TrimSpace(body[loc[2]:loc[3]])
				// Taint heuristic: user-controlled if uses function param or msg.sender or msg.data
				tainted := strings.Contains(arg, "msg.sender") || strings.Contains(arg, "msg.data")
				if !tainted {
					for _, p := range params {
						if strings.Contains(arg, p) {
							tainted = true
							break
						}
					}
				}
				if !tainted {
					continue // reduce noise: only report if likely tainted
				}
				sHeader, _ := util.FindLineRange(content, header)
				// best-effort line number for the call
				sCall, _ := util.FindLineRange(body, full)
				start := sHeader + sCall
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityCritical,
					Confidence:  0.7,
					DetectorID:  "solidity-unsafe-delegatecall",
					File:        file,
					StartLine:   start,
					EndLine:     start,
					Snippet:     util.ExtractSnippet(content, start, start, 8),
					Message:     "delegatecall target derived from user-controlled input",
					Rationale:   "delegatecall executes in caller context; untrusted targets can corrupt storage and take over.",
					Remediation: "Restrict and validate delegatecall targets. Use UUPS/transparent proxy patterns with access control.",
					References:  []string{"SWC-112"},
					Fingerprint: util.Fingerprint(d.Meta().ID, file, start, start, strings.TrimSpace(full)),
				})
			}
		}
	}
	return findings, nil
}
