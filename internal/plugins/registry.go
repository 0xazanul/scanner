package plugins

import (
	"context"
	"path/filepath"

	"github.com/xab-mack/smartscanner/internal/model"
)

type Detector interface {
	Meta() model.RuleMeta
	Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error)
}

type Registry struct {
	detectors []Detector
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(d Detector) { r.detectors = append(r.detectors, d) }

func (r *Registry) RegisterBuiltin() {
	r.Register(&solidityHeuristics{})
	r.Register(&goFabricHeuristics{})
}

func (r *Registry) Run(ctx context.Context, req model.ScanRequest) []model.Finding {
	var out []model.Finding
	for _, d := range r.detectors {
		fs, err := d.Analyze(ctx, req)
		if err == nil {
			// normalize file paths
			for i := range fs {
				fs[i].File = filepath.ToSlash(fs[i].File)
			}
			out = append(out, fs...)
		}
	}
	return out
}

func (r *Registry) Detectors() []Detector { return r.detectors }
