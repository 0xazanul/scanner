package tools

import "encoding/json"

// Mythril JSON (simplified)
type mythIssue struct {
	SwcID       string `json:"swcID"`
	Description string `json:"description"`
	Locations   []struct {
		SourceMap string `json:"sourceMap"`
	} `json:"locations"`
}
type mythOut struct {
	Issues []mythIssue `json:"issues"`
}

func normalizeMythril(raw []byte) ([]Finding, error) {
	var o mythOut
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, err
	}
	// SourceMap parsing omitted; set line 1 for now
	var out []Finding
	for _, i := range o.Issues {
		out = append(out, Finding{RuleID: i.SwcID, Severity: "high", Confidence: 0.7, File: "", StartLine: 1, EndLine: 1, Message: i.Description})
	}
	return out, nil
}
