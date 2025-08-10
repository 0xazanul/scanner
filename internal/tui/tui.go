package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xab-mack/smartscanner/internal/model"
)

type modelT struct {
	findings []model.Finding
	cursor   int
}

func initialModel(findings []model.Finding) modelT { return modelT{findings: findings} }

func (m modelT) Init() tea.Cmd                           { return nil }
func (m modelT) Update(msg tea.Msg) (tea.Model, tea.Cmd) { return m, nil }
func (m modelT) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Findings (%d)\n\n", len(m.findings))
	// group by file
	groups := map[string][]model.Finding{}
	for _, f := range m.findings {
		groups[f.File] = append(groups[f.File], f)
	}
	for file, fs := range groups {
		fmt.Fprintf(&b, "%s\n", file)
		for _, f := range fs {
			fmt.Fprintf(&b, "  - %s [%s] L%d: %s (conf=%.2f)\n", f.RuleID, f.Severity, f.StartLine, f.Message, f.Confidence)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// Run launches a minimal TUI list view
func Run(findings []model.Finding) error {
	p := tea.NewProgram(initialModel(findings))
	_, err := p.Run()
	return err
}
