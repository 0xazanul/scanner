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

// soliditySelfdestruct flags selfdestruct usage in public/external paths or with tainted target
type soliditySelfdestruct struct{}

func (d *soliditySelfdestruct) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-SELFDESTRUCT", Title: "selfdestruct reachable via public/external path or arbitrary address", Severity: model.SeverityCritical}
}

func (d *soliditySelfdestruct) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *soliditySelfdestruct) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}

	reHeader := regexp.MustCompile(`(?m)function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)?[^\{]*\{`)
	reSD := regexp.MustCompile(`(?i)selfdestruct\s*\(([^)]+)\)`)

	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		// Quick skip
		if !strings.Contains(strings.ToLower(content), "selfdestruct(") {
			continue
		}
		// Split into functions and scan bodies
		matches := reHeader.FindAllStringIndex(content, -1)
		for i, m := range matches {
			header := content[m[0]:m[1]]
			funcBody := content[m[1]:]
			// trim body to before next function header
			if i+1 < len(matches) {
				funcBody = content[m[1]:matches[i+1][0]]
			}
			nameParts := reHeader.FindStringSubmatch(header)
			fnName := ""
			visibility := ""
			params := []string{}
			if len(nameParts) >= 2 {
				fnName = nameParts[1]
			}
			if len(nameParts) >= 4 {
				visibility = strings.ToLower(nameParts[3])
			}
			// collect parameter identifiers (naive)
			if len(nameParts) >= 3 {
				rawParams := nameParts[2]
				for _, p := range strings.Split(rawParams, ",") {
					p = strings.TrimSpace(p)
					if p == "" {
						continue
					}
					// take last token as name
					parts := strings.Fields(p)
					if len(parts) > 0 {
						paramName := parts[len(parts)-1]
						// drop trailing commas or memory/calldata indicators already stripped
						paramName = strings.Trim(paramName, ",) ")
						// ignore types like address payable
						if isIdentifier(paramName) {
							params = append(params, paramName)
						}
					}
				}
			}
			// search selfdestruct occurrences in body
			bodyLower := strings.ToLower(funcBody)
			locs := reSD.FindAllStringSubmatchIndex(bodyLower, -1)
			if len(locs) == 0 {
				continue
			}
			for _, loc := range locs {
				full := funcBody[loc[0]:loc[1]]
				arg := strings.TrimSpace(funcBody[loc[2]:loc[3]])
				// determine severity/notes
				sev := model.SeverityHigh
				msg := "selfdestruct present; ensure it is restricted and target is safe"
				if visibility == "public" || visibility == "external" {
					sev = model.SeverityCritical
					msg = "selfdestruct reachable via public/external function"
				}
				// taint: if arg references a function parameter or msg.sender, escalate
				for _, p := range params {
					if strings.Contains(arg, p) || strings.Contains(arg, "msg.sender") {
						sev = model.SeverityCritical
						msg = "selfdestruct target derived from user input"
						break
					}
				}
				// lower severity if clearly constant (address(0) or known literal)
				if strings.Contains(arg, "address(0)") || regexp.MustCompile(`^address\s*\([^)]*\)$`).MatchString(arg) {
					if sev != model.SeverityCritical {
						sev = model.SeverityHigh
					}
				}
				// compute line range approx from header start to body occurrence
				start, end := util.FindLineRange(content, header)
				// adjust end to include the selfdestruct line
				sdStart, _ := util.FindLineRange(funcBody, full)
				if sdStart > 0 {
					start = start + sdStart // rough position inside body
					end = start
				}
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    sev,
					Confidence:  0.7,
					DetectorID:  "solidity-selfdestruct",
					File:        file,
					Entity:      fnName,
					StartLine:   start,
					EndLine:     end,
					Snippet:     util.ExtractSnippet(content, start, end, 8),
					Message:     msg,
					Rationale:   "Contracts using selfdestruct can be permanently disabled or leak funds to attacker-controlled addresses.",
					Remediation: "Avoid selfdestruct; if needed, restrict via onlyOwner/timelock and use fixed, vetted payout addresses.",
					References:  []string{"SWC-106"},
					Fingerprint: util.Fingerprint(d.Meta().ID, file, start, end, fnName+":"+strings.TrimSpace(full)),
				})
			}
		}
	}
	return findings, nil
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	// must start with letter or underscore
	c := s[0]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
		return false
	}
	for i := 1; i < len(s); i++ {
		ch := s[i]
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return false
		}
	}
	return true
}
