package model

import "time"

type Language string

const (
	LangSolidity Language = "solidity"
	LangGo       Language = "go"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func ParseSeverity(s string) Severity {
	switch s {
	case string(SeverityCritical):
		return SeverityCritical
	case string(SeverityHigh):
		return SeverityHigh
	case string(SeverityMedium):
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func SeverityGTE(a, b Severity) bool {
	order := map[Severity]int{SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4}
	return order[a] >= order[b]
}

type RuleMeta struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Tags        []string `json:"tags"`
	SupportsFix bool     `json:"supportsFix"`
}

type Finding struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Confidence  float64  `json:"confidence"`
    DetectorID  string   `json:"detectorId"`
	File        string   `json:"file"`
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	Snippet     string   `json:"snippet"`
	Entity      string   `json:"entity"`
	Message     string   `json:"message"`
	Rationale   string   `json:"rationale"`
    Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	Fingerprint string   `json:"fingerprint"`
}

type ScanRequest struct {
    Path        string
    DeltaOnly   bool
    TimeBudget  time.Duration
    ConfigPath  string
}

type ScanResult struct {
	Findings []Finding     `json:"findings"`
	Elapsed  time.Duration `json:"elapsed"`
}
