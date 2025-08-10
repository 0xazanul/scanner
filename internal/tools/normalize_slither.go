package tools

import "encoding/json"

// Slither JSON (simplified)
type slitherLocation struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
}
type slitherDetection struct {
	Check       string `json:"check"`
	Impact      string `json:"impact"`
	Confidence  string `json:"confidence"`
	Description string `json:"description"`
	Elements    []struct {
		SourceMapping slitherLocation `json:"source_mapping"`
	} `json:"elements"`
}
type slitherOut struct {
	Results struct {
		Detectors []slitherDetection `json:"detectors"`
	} `json:"results"`
}

func normalizeSlither(raw []byte) ([]Finding, error) {
	var o slitherOut
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, err
	}
	var out []Finding
	for _, d := range o.Results.Detectors {
		sev := "low"
		if d.Impact == "High" || d.Impact == "Critical" {
			sev = "high"
		} else if d.Impact == "Medium" {
			sev = "medium"
		}
		conf := 0.6
		if d.Confidence == "High" {
			conf = 0.85
		} else if d.Confidence == "Medium" {
			conf = 0.7
		}
		file := ""
		line := 1
		if len(d.Elements) > 0 {
			file = d.Elements[0].SourceMapping.Filename
			line = d.Elements[0].SourceMapping.Line
		}
		out = append(out, Finding{RuleID: d.Check, Severity: sev, Confidence: conf, File: file, StartLine: line, EndLine: line, Message: d.Description})
	}
	return out, nil
}
