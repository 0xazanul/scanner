package tools

import "encoding/json"

// Gosec JSON (simplified)
type gosecIssue struct {
	RuleID   string `json:"rule_id"`
	Details  string `json:"details"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
}
type gosecOut struct {
	Issues []gosecIssue `json:"Issues"`
}

func normalizeGosec(raw []byte) ([]Finding, error) {
	var o gosecOut
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, err
	}
	var out []Finding
	for _, i := range o.Issues {
		out = append(out, Finding{RuleID: i.RuleID, Severity: i.Severity, Confidence: 0.6, File: i.File, StartLine: i.Line, EndLine: i.Line, Message: i.Details})
	}
	return out, nil
}
