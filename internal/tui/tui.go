package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xab-mack/smartscanner/internal/model"
)

type modelT struct {
	findings       []model.Finding
	files          []string
	fileToFindings map[string][]model.Finding
	narration      []string
	selFile        int
	selFinding     int
	focusLeft      bool
	severityFilter model.Severity
	ruleFilter     string
}

func initialModel(findings []model.Finding) modelT {
	m := modelT{findings: findings, fileToFindings: map[string][]model.Finding{}, focusLeft: true}
	for _, f := range findings {
		m.fileToFindings[f.File] = append(m.fileToFindings[f.File], f)
	}
	for file := range m.fileToFindings {
		m.files = append(m.files, file)
	}
	sort.Strings(m.files)
	m.narration = append(m.narration, "Scan complete. Arrow keys navigate. Left/Right switch panes. Enter shows details. q to quit.")
	return m
}

func (m modelT) Init() tea.Cmd { return nil }
func (m modelT) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "left", "h":
			m.focusLeft = true
		case "right", "l":
			m.focusLeft = false
			m.selFinding = 0
		case "up", "k":
			if m.focusLeft {
				if m.selFile > 0 {
					m.selFile--
				}
				m.selFinding = 0
			} else {
				if m.selFinding > 0 {
					m.selFinding--
				}
			}
		case "down", "j":
			if m.focusLeft {
				if m.selFile < len(m.files)-1 {
					m.selFile++
				}
				m.selFinding = 0
			} else {
				cur := m.currentFindings()
				if m.selFinding < len(cur)-1 {
					m.selFinding++
				}
			}
		case "s":
			switch m.severityFilter {
			case model.SeverityLow:
				m.severityFilter = model.SeverityMedium
			case model.SeverityMedium:
				m.severityFilter = model.SeverityHigh
			case model.SeverityHigh:
				m.severityFilter = model.SeverityCritical
			default:
				m.severityFilter = model.SeverityLow
			}
			m.narration = append(m.narration, fmt.Sprintf("Filter: severity >= %s", m.severityFilter))
		case "r":
			cur := m.currentFindings()
			if len(cur) > 0 {
				f := cur[m.selFinding]
				if m.ruleFilter == f.RuleID {
					m.ruleFilter = ""
				} else {
					m.ruleFilter = f.RuleID
				}
				if m.ruleFilter == "" {
					m.narration = append(m.narration, "Rule filter cleared")
				} else {
					m.narration = append(m.narration, "Filter: rule="+m.ruleFilter)
				}
			}
		case "i":
			cur := m.currentFindings()
			if len(cur) > 0 {
				f := cur[m.selFinding]
				sup := fmt.Sprintf("// scanner:ignore %s reason=\"false positive\"", f.RuleID)
				m.narration = append(m.narration, "Add inline suppression above line: "+sup)
			}
		case "enter":
			cur := m.currentFindings()
			if len(cur) > 0 {
				f := cur[m.selFinding]
				m.narration = append(m.narration, fmt.Sprintf("Inspecting %s at %s:%d: %s", f.RuleID, f.File, f.StartLine, f.Message))
			}
		}
	}
	return m, nil
}

func (m modelT) currentFindings() []model.Finding {
	if len(m.files) == 0 {
		return nil
	}
	file := m.files[m.selFile]
	items := m.fileToFindings[file]
	var out []model.Finding
	for _, f := range items {
		if m.ruleFilter != "" && f.RuleID != m.ruleFilter {
			continue
		}
		if m.severityFilter != "" && !model.SeverityGTE(f.Severity, m.severityFilter) {
			continue
		}
		out = append(out, f)
	}
	return out
}
func (m modelT) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Findings (%d)\n\n", len(m.findings))
	b.WriteString("Files:\n")
	for i, file := range m.files {
		prefix := "  "
		if m.focusLeft && i == m.selFile {
			prefix = "> "
		}
		b.WriteString(prefix + file + "\n")
	}
	b.WriteString("\nDetails:\n")
	cur := m.currentFindings()
	for i, f := range cur {
		prefix := "  "
		if !m.focusLeft && i == m.selFinding {
			prefix = "> "
		}
		fmt.Fprintf(&b, "%s%s [%s] L%d-%d: %s (conf=%.2f)\n", prefix, f.RuleID, f.Severity, f.StartLine, f.EndLine, f.Message, f.Confidence)
	}
	if len(cur) == 0 {
		b.WriteString("  (no findings for this file)\n")
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
