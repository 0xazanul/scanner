package engine

import "github.com/xab-mack/smartscanner/internal/model"

// Exported wrappers for CLI use without import cycles
func WriteBaseline(path string, findings []model.Finding) error { return writeBaseline(path, findings) }
