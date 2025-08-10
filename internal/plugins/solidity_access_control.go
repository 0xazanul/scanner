package plugins

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// solidityAccessControl flags state-changing external/public functions without obvious access checks
type solidityAccessControl struct{}

func (d *solidityAccessControl) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-ACCESS-CONTROL", Title: "Potential missing access control on state-changing function", Severity: model.SeverityHigh}
}

func (d *solidityAccessControl) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityAccessControl) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	for _, path := range solACFiles(pc, req.Path) {
		content := solACContent(pc, path)
		if content == "" {
			b, _ := os.ReadFile(path)
			content = string(b)
		}
		// naive function header regex for public/external
		reHeader := regexp.MustCompile(`(?m)function\s+(\w+)\s*\([^)]*\)\s*(public|external)\b[^\{]*\{`)
		headers := reHeader.FindAllStringIndex(content, -1)
		for _, h := range headers {
			header := content[h[0]:h[1]]
			// modifiers check
			hasModifier := strings.Contains(header, "onlyOwner") || strings.Contains(header, "onlyAdmin") || strings.Contains(header, "onlyRole(")
			// function body slice (approximate): from '{' at end of header to matching '}' or next header
			bodyStart := strings.Index(header, "{")
			if bodyStart < 0 {
				continue
			}
			// get from absolute index of '{'
			open := h[0] + bodyStart
			body := content[open:]
			nextIdx := reHeader.FindStringIndex(body)
			if nextIdx != nil {
				body = body[:nextIdx[0]]
			}
			// state change heuristic: assignment to storage-like identifiers (no 'memory')
			changesState := regexp.MustCompile(`(?m)\b[_a-zA-Z][\w]*\s*=`).FindStringIndex(body) != nil
			// access check heuristic in body
			hasRequire := strings.Contains(body, "require(") && (strings.Contains(body, "msg.sender") || strings.Contains(strings.ToLower(body), "hasrole"))
			if changesState && !(hasModifier || hasRequire) {
				start, end := util.FindLineRange(content, header)
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityHigh,
					Confidence:  0.6,
					DetectorID:  "solidity-access-control",
					File:        path,
					StartLine:   start,
					EndLine:     end,
					Snippet:     util.ExtractSnippet(content, start, end, 8),
					Message:     "Public/external state-changing function without clear access control",
					Rationale:   "Functions modifying state should restrict callers via modifiers or role checks",
					Remediation: "Add appropriate access control (e.g., onlyOwner/onlyRole) or explicit require() checks.",
					References:  []string{"SWC-105", "SWC-106"},
					Fingerprint: util.Fingerprint(d.Meta().ID, path, start, end, header),
				})
			}
		}
	}
	return findings, nil
}

func solACFiles(pc *analysis.ProjectContext, root string) []string {
	if pc != nil && len(pc.SolidityFiles) > 0 {
		return pc.SolidityFiles
	}
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".sol") {
			out = append(out, path)
		}
		return nil
	})
	return out
}

func solACContent(pc *analysis.ProjectContext, path string) string {
	if pc != nil {
		if c, ok := pc.FileContents[path]; ok {
			return c
		}
	}
	return ""
}
