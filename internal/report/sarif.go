package report

import (
	"encoding/json"

	"github.com/xab-mack/smartscanner/internal/model"
)

type sarif struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID    string       `json:"ruleId"`
	Level     string       `json:"level"`
	Message   sarifMessage `json:"message"`
	Locations []sarifLoc   `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLoc struct {
	Physical sarifPhys `json:"physicalLocation"`
}
type sarifPhys struct {
	ArtifactLocation sarifArt    `json:"artifactLocation"`
	Region           sarifRegion `json:"region"`
}
type sarifArt struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

func ToSARIF(findings []model.Finding) ([]byte, error) {
	var results []sarifResult
	for _, f := range findings {
		level := "note"
		switch f.Severity {
		case model.SeverityLow:
			level = "note"
		case model.SeverityMedium:
			level = "warning"
		case model.SeverityHigh, model.SeverityCritical:
			level = "error"
		}
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   level,
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLoc{{Physical: sarifPhys{
				ArtifactLocation: sarifArt{URI: f.File},
				Region:           sarifRegion{StartLine: f.StartLine, EndLine: f.EndLine},
			}}},
		})
	}
	s := sarif{Version: "2.1.0", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "smartscanner"}}, Results: results}}}
	return json.MarshalIndent(s, "", "  ")
}
