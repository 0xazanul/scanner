package util

import (
	"strings"
)

// FindLineRange finds the start and end line numbers (1-based) for the first occurrence
// of needle in content. If not found, returns (1,1).
func FindLineRange(content, needle string) (start, end int) {
	if needle == "" {
		return 1, 1
	}
	idx := strings.Index(content, needle)
	if idx < 0 {
		return 1, 1
	}
	before := content[:idx]
	start = strings.Count(before, "\n") + 1
	end = start + strings.Count(needle, "\n")
	return
}

// ExtractSnippet returns up to maxLines lines around the [start,end] region.
func ExtractSnippet(content string, start, end, maxLines int) string {
	if maxLines <= 0 {
		maxLines = 8
	}
	lines := strings.Split(content, "\n")
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start
	}
	s := start - 1
	e := end - 1
	// expand context
	ctx := maxLines
	s = max(0, s-ctx/2)
	e = min(len(lines)-1, e+ctx/2)
	return strings.Join(lines[s:e+1], "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
