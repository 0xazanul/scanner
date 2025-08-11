package plugins

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/xab-mack/smartscanner/internal/model"
)

// DetectorV2 supports rich project context (placeholder type for future)
type DetectorV2 interface {
	Meta() model.RuleMeta
	Analyze(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error)
}

// Detector is the legacy interface (kept for compatibility)
type Detector interface {
	Meta() model.RuleMeta
	Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error)
}

type Registry struct{ detectors []any }

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(d any) { r.detectors = append(r.detectors, d) }

func (r *Registry) RegisterBuiltin() {
	r.Register(&solidityHeuristics{})
	r.Register(&goFabricHeuristics{})
	r.Register(&solidityUncheckedCalls{})
	r.Register(&solidityMissingEvents{})
	r.Register(&solidityAccessControl{})
	r.Register(&fabricIdentityEndorsement{})
	r.Register(&fabricSSARules{})
	r.Register(&solidityReentrancy{})
	r.Register(&solidityRandomness{})
	r.Register(&fabricFunctionRules{})
	r.Register(&solidityProxyUpgrade{})
	r.Register(&solidityFallbackReceive{})
	r.Register(&fabricSSAStrict{})
	r.Register(&solidityStorageLayout{})
	r.Register(&solidityMEV{})
	r.Register(&solidityReentrancyPath{})
	// newly added
	r.Register(&soliditySelfdestruct{})
	r.Register(&solidityUninitializedStorage{})
	r.Register(&solidityFloatingPragma{})
	r.Register(&solidityDelegatecallUnsafe{})
	r.Register(&solidityOwnerRisk{})
	r.Register(&solidityNonImmutableAddresses{})
	r.Register(&solidityMsgValueChecks{})
}

func (r *Registry) Run(ctx context.Context, req model.ScanRequest) []model.Finding {
	cpu := runtime.NumCPU()
	if cpu < 2 {
		cpu = 2
	}
	type res struct{ fs []model.Finding }
	ch := make(chan res, len(r.detectors))
	var wg sync.WaitGroup
	sem := make(chan struct{}, cpu)
	for _, d := range r.detectors {
		d := d
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var fs []model.Finding
			var err error
			switch det := d.(type) {
			case DetectorV2:
				fs, err = det.Analyze(ctx, nil, req)
			case Detector:
				fs, err = det.Analyze(ctx, req)
			default:
				err = nil
			}
			if err != nil {
				ch <- res{}
				return
			}
			for i := range fs {
				fs[i].File = filepath.ToSlash(fs[i].File)
			}
			ch <- res{fs: fs}
		}()
	}
	wg.Wait()
	close(ch)
	var out []model.Finding
	for r := range ch {
		out = append(out, r.fs...)
	}
	return out
}

// RunWithContext passes a project context to detectors that implement DetectorV2
func (r *Registry) RunWithContext(ctx context.Context, projectContext any, req model.ScanRequest) []model.Finding {
	cpu := runtime.NumCPU()
	if cpu < 2 {
		cpu = 2
	}
	type res struct{ fs []model.Finding }
	ch := make(chan res, len(r.detectors))
	var wg sync.WaitGroup
	sem := make(chan struct{}, cpu)
	for _, d := range r.detectors {
		d := d
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var fs []model.Finding
			var err error
			switch det := d.(type) {
			case DetectorV2:
				fs, err = det.Analyze(ctx, projectContext, req)
			case Detector:
				fs, err = det.Analyze(ctx, req)
			default:
				err = nil
			}
			if err != nil {
				ch <- res{}
				return
			}
			for i := range fs {
				fs[i].File = filepath.ToSlash(fs[i].File)
			}
			ch <- res{fs: fs}
		}()
	}
	wg.Wait()
	close(ch)
	var out []model.Finding
	for r := range ch {
		out = append(out, r.fs...)
	}
	return out
}

func (r *Registry) Detectors() []any { return r.detectors }
