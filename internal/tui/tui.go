package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xab-mack/smartscanner/internal/model"
)

type modelT struct {
	findings       []model.Finding
	cursor         int
	files          []string
	fileToFindings map[string][]model.Finding
	narration      []string
}

func initialModel(findings []model.Finding) modelT {
	m := modelT{findings: findings, fileToFindings: map[string][]model.Finding{}}
	for _, f := range findings {
		m.fileToFindings[f.File] = append(m.fileToFindings[f.File], f)
	}
	for file := range m.fileToFindings {
		m.files = append(m.files, file)
	}
	m.narration = append(m.narration, "Scan complete. Use --format json or --sarif for machine output.")
	return m
}

func (m modelT) Init() tea.Cmd                           { return nil }
func (m modelT) Update(msg tea.Msg) (tea.Model, tea.Cmd) { return m, nil }
func (m modelT) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Findings (%d)\n\n", len(m.findings))
	for _, file := range m.files {
		fmt.Fprintf(&b, "%s\n", file)
		for _, f := range m.fileToFindings[file] {
			fmt.Fprintf(&b, "  - %s [%s] L%d: %s (conf=%.2f)\n", f.RuleID, f.Severity, f.StartLine, f.Message, f.Confidence)
		}
		b.WriteString("\n")
	}
	if len(m.narration) > 0 {
		b.WriteString("Narration:\n")
		for _, n := range m.narration {
			b.WriteString("  " + n + "\n")
		}
	}
	return b.String()
}

// Run launches a minimal TUI list view
func Run(findings []model.Finding) error {
	p := tea.NewProgram(initialModel(findings))
	_, err := p.Run()
	return err
}
