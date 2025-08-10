package tools

import (
	"encoding/json"
)

// Solhint JSON schema (simplified)
type solhintMsg struct {
	RuleId   string `json:"ruleId"`
	Message  string `json:"message"`
	Severity int    `json:"severity"`
	Line     int    `json:"line"`
	EndLine  int    `json:"endLine"`
}
type solhintFile struct {
	FilePath string       `json:"filePath"`
	Messages []solhintMsg `json:"messages"`
}

func normalizeSolhint(raw []byte) ([]Finding, error) {
	var files []solhintFile
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range files {
		for _, m := range f.Messages {
			sev := "low"
			if m.Severity >= 2 {
				sev = "medium"
			}
			if m.Severity >= 3 {
				sev = "high"
			}
			out = append(out, Finding{
				RuleID:     m.RuleId,
				Severity:   sev,
				Confidence: 0.5,
				File:       f.FilePath,
				StartLine:  m.Line,
				EndLine:    m.EndLine,
				Message:    m.Message,
			})
		}
	}
	return out, nil
}
