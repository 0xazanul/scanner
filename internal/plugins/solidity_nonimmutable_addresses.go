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

// solidityNonImmutableAddresses flags critical addresses set in constructor but not immutable
type solidityNonImmutableAddresses struct{}

func (d *solidityNonImmutableAddresses) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-NONIMM-ADDR", Title: "Critical addresses not immutable", Severity: model.SeverityLow}
}

func (d *solidityNonImmutableAddresses) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityNonImmutableAddresses) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reState := regexp.MustCompile(`(?m)^\s*address\s+(public|private|internal|external)?\s*(immutable\s+)?(\w+)\s*;`)
	reCtor := regexp.MustCompile(`(?m)constructor\s*\([^)]*\)\s*`) // rough
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		// collect address vars
		stateMatches := reState.FindAllStringSubmatchIndex(content, -1)
		for _, m := range stateMatches {
			// m indices: full, vis grp, immutable grp, name grp
			immutableSpanStart := m[4]
			immutableSpanEnd := m[5]
			nameStart := m[6]
			nameEnd := m[7]
			if immutableSpanStart != -1 && immutableSpanEnd != -1 {
				continue // already immutable
			}
			name := content[nameStart:nameEnd]
			// Heuristic: consider names indicating critical pointers
			lowerName := strings.ToLower(name)
			if !(strings.Contains(lowerName, "owner") || strings.Contains(lowerName, "admin") || strings.Contains(lowerName, "oracle") || strings.Contains(lowerName, "token") || strings.Contains(lowerName, "router") || strings.Contains(lowerName, "treasury")) {
				continue
			}
			// Check if assigned in constructor
			ctorIdx := reCtor.FindStringIndex(content)
			if ctorIdx == nil {
				continue
			}
			ctorBody := content[ctorIdx[1]:]
			// restrict to first contract's constructor roughly up to next function
			if next := regexp.MustCompile(`(?m)^\s*function\s+`).FindStringIndex(ctorBody); next != nil {
				ctorBody = ctorBody[:next[0]]
			}
			assigned := regexp.MustCompile(`(?m)\b`+regexp.QuoteMeta(name)+`\s*=\s*`).FindStringIndex(ctorBody) != nil
			if !assigned {
				continue
			}
			s, e := util.FindLineRange(content, content[m[0]:m[1]])
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityLow,
				Confidence:  0.65,
				DetectorID:  "solidity-nonimmutable-addresses",
				File:        file,
				StartLine:   s,
				EndLine:     e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "Critical address set in constructor but not marked immutable",
				Rationale:   "Immutables prevent later modification and enable compiler optimizations.",
				Remediation: "Mark critical addresses as immutable if they should never change.",
				References:  []string{"best-practices"},
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, name),
			})
		}
	}
	return findings, nil
}
