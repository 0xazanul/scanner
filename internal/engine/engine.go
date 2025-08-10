package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/xab-mack/smartscanner/internal/config"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/plugins"
)

type Engine struct {
	registry *plugins.Registry
}

func New() *Engine {
	reg := plugins.NewRegistry()
	reg.RegisterBuiltin()
	return &Engine{registry: reg}
}

func (e *Engine) Scan(ctx context.Context, req model.ScanRequest) (*model.ScanResult, error) {
	start := time.Now()
	// Prepare file list (optionally delta)
	files := discoverFiles(req.Path, req.DeltaOnly)
	_ = files // placeholder for future schedulers
	// TODO: Build AST/IR per language and hand to detectors
	findings := e.registry.Run(ctx, req)
	// load config and apply ignores
	cfg, _, _ := config.Load(req.Path)
	findings = applyIgnores(findings, cfg)
	elapsed := time.Since(start)
	return &model.ScanResult{Findings: findings, Elapsed: elapsed}, nil
}

// discoverFiles returns relevant source files; if deltaOnly, restrict using git status
func discoverFiles(root string, deltaOnly bool) []string {
	var out []string
	if deltaOnly {
		// best-effort: if .git exists, read changed files via index
		// For now, fall back to full scan; integrate git plumbing later
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lower := filepath.Ext(d.Name())
		switch lower {
		case ".sol", ".go":
			out = append(out, path)
		}
		return nil
	})
	return out
}

// hashFile computes sha256 of a file for caching keys
func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
