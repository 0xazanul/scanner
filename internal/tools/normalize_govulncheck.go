package tools

import "encoding/json"

// Govulncheck JSON (simplified)
type gvFinding struct {
	ID        string `json:"id"`
	Pkg       string `json:"pkg"`
	Module    string `json:"module"`
	CallStack []struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"callstack"`
}
type gvOut struct {
	Findings []gvFinding `json:"findings"`
}

func normalizeGovulncheck(raw []byte) ([]Finding, error) {
	var o gvOut
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range o.Findings {
		file, line := "", 1
		if len(f.CallStack) > 0 {
			file = f.CallStack[0].File
			line = f.CallStack[0].Line
		}
		out = append(out, Finding{RuleID: f.ID, Severity: "high", Confidence: 0.7, File: file, StartLine: line, EndLine: line, Message: f.Pkg + " vulnerable (" + f.Module + ")"})
	}
	return out, nil
}
