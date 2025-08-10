package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/config"
	"github.com/xab-mack/smartscanner/internal/goanalysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/plugins"
	"github.com/xab-mack/smartscanner/internal/solidity"
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
	// Build project context (solidity ASTs for now)
	pctx := &analysis.ProjectContext{RootPath: req.Path, Files: files, FileContents: map[string]string{}, SolidityAST: map[string]*solidity.ASTCompact{}}
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			pctx.FileContents[f] = string(b)
		}
		if filepath.Ext(f) == ".sol" {
			pctx.SolidityFiles = append(pctx.SolidityFiles, f)
		}
		if filepath.Ext(f) == ".go" {
			pctx.GoFiles = append(pctx.GoFiles, f)
		}
	}
	// parse concurrently (simple fan-out/fan-in)
	parseSolidityASTsConcurrently(pctx)
	// build lightweight IR and cache it; also build trivial CFG
	for _, f := range pctx.SolidityFiles {
		if c, ok := pctx.FileContents[f]; ok {
			_, _ = solidity.BuildIR(f, c)
			_, _ = analysis.BuildCFG(f, c)
		}
	}
	// load Go packages and SSA
	if len(pctx.GoFiles) > 0 {
		if pkgs, err := goanalysis.LoadPackages(req.Path); err == nil {
			pctx.GoPackages = pkgs
			prog, ssaPkgs := goanalysis.BuildSSA(pkgs)
			pctx.SSAProgram = prog
			pctx.SSAPackages = ssaPkgs
		}
	}
	findings := e.registry.RunWithContext(ctx, pctx, req)
	// external tools within remaining budget (best-effort)
	if cfg, _, err := config.Load(req.Path); err == nil {
		budget := req.TimeBudget
		if budget <= 0 {
			budget = 3 * time.Second
		}
		ext := runExternalTools(ctx, cfg, pctx, req.Path, budget/2)
		findings = append(findings, ext...)
	}
	// baseline filtering if configured
	if cfg, cfgPath, err := config.Load(req.Path); err == nil && cfg.BaselinePath != "" {
		if b, err := loadBaseline(cfg.BaselinePath); err == nil {
			findings = filterByBaseline(findings, b)
			_ = cfgPath
		}
	}
	// load config and apply ignores, then calibrate
	cfg, _, _ := config.Load(req.Path)
	findings = applyIgnores(findings, cfg)
	findings = calibrateFindings(findings)
	elapsed := time.Since(start)
	return &model.ScanResult{Findings: findings, Elapsed: elapsed}, nil
}

// discoverFiles returns relevant source files; if deltaOnly, restrict using git status
func discoverFiles(root string, deltaOnly bool) []string {
	var out []string
	if deltaOnly {
		if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
			// use git to list changes vs HEAD (fallback to all on error)
			changed := gitChanged(root)
			if len(changed) > 0 {
				return changed
			}
		}
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

func gitChanged(root string) []string {
	// git diff --name-only --diff-filter=ACMRT HEAD
	// avoid using os/exec here for portability; if unavailable, return nil
	// Minimal implementation using exec allowed:
	exe, err := execLookPath("git")
	if err != nil {
		return nil
	}
	out, err := runCmd(exe, root, []string{"diff", "--name-only", "--diff-filter=ACMRT", "HEAD"})
	if err != nil {
		return nil
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		ext := filepath.Ext(line)
		if ext == ".sol" || ext == ".go" {
			files = append(files, filepath.Join(root, line))
		}
	}
	return files
}

func parseSolidityASTsConcurrently(pctx *analysis.ProjectContext) {
	type item struct{ file string }
	files := make(chan item, len(pctx.SolidityFiles))
	for _, f := range pctx.SolidityFiles {
		files <- item{file: f}
	}
	close(files)
	workers := 4
	done := make(chan struct{}, workers)
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		go func() {
			for it := range files {
				if ast, err := solidity.ParseWithSolc(it.file, ""); err == nil {
					mu.Lock()
					pctx.SolidityAST[it.file] = ast
					mu.Unlock()
				}
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
}

// lightweight wrappers to allow testing; use os/exec
var execLookPath = func(name string) (string, error) { return exec.LookPath(name) }
var runCmd = func(bin, dir string, args []string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	b, err := cmd.Output()
	return string(b), err
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
