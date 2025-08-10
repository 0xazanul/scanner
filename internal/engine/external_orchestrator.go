package engine

import (
	"context"
	"time"

	"github.com/xab-mack/smartscanner/internal/config"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/tools"
)

// runExternalTools executes enabled tools within budget and converts them to model findings
func runExternalTools(ctx context.Context, cfg config.Config, path string, budget time.Duration) []model.Finding {
	var out []model.Finding
	// split budget per tool crudely
	per := budget / 3
	ctxSlither, cancelS := context.WithTimeout(ctx, per)
	defer cancelS()
	if cfg.ExternalTools.Slither {
		res := tools.RunWithTimeout(ctxSlither, "slither", "--json", "-", path)
		if res.Err == nil {
			fs, _ := tools.Normalize("slither", res.Raw)
			out = append(out, convertExternal(fs, "slither")...)
		}
	}
	ctxSolhint, cancelH := context.WithTimeout(ctx, per)
	defer cancelH()
	if cfg.ExternalTools.Solhint {
		res := tools.RunWithTimeout(ctxSolhint, "solhint", "-f", "json", path)
		if res.Err == nil {
			fs, _ := tools.Normalize("solhint", res.Raw)
			out = append(out, convertExternal(fs, "solhint")...)
		}
	}
	ctxGosec, cancelG := context.WithTimeout(ctx, per)
	defer cancelG()
	if cfg.ExternalTools.Gosec {
		res := tools.RunWithTimeout(ctxGosec, "gosec", "-fmt=json", "./...")
		if res.Err == nil {
			fs, _ := tools.Normalize("gosec", res.Raw)
			out = append(out, convertExternal(fs, "gosec")...)
		}
	}
	return out
}

func convertExternal(ext []tools.Finding, source string) []model.Finding {
	var out []model.Finding
	for _, f := range ext {
		sev := model.ParseSeverity(f.Severity)
		conf := f.Confidence
		if conf == 0 {
			conf = 0.5
		}
		out = append(out, model.Finding{
			RuleID:     source + ":" + f.RuleID,
			Severity:   sev,
			Confidence: conf,
			DetectorID: "external:" + source,
			File:       f.File,
			StartLine:  f.StartLine,
			EndLine:    f.EndLine,
			Message:    f.Message,
		})
	}
	return out
}
