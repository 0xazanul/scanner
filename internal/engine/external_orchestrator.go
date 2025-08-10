package engine

import (
	"context"
	"time"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/config"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/tools"
)

// runExternalTools executes enabled tools within budget and converts them to model findings
func runExternalTools(ctx context.Context, cfg config.Config, pctx *analysis.ProjectContext, root string, budget time.Duration) []model.Finding {
	var out []model.Finding
	if budget <= 0 {
		return out
	}
	// split budget per tool crudely
	per := budget / 4
	if cfg.ExternalTools.Slither {
		ctxSlither, cancelS := context.WithTimeout(ctx, per)
		res := tools.RunWithTimeout(ctxSlither, "slither", "--json", "-", root)
		cancelS()
		if res.Err == nil {
			fs, _ := tools.Normalize("slither", res.Raw)
			out = append(out, convertExternal(fs, "slither")...)
		}
	}
	if cfg.ExternalTools.Solhint {
		ctxSolhint, cancelH := context.WithTimeout(ctx, per)
		res := tools.RunWithTimeout(ctxSolhint, "solhint", "-f", "json", root)
		cancelH()
		if res.Err == nil {
			fs, _ := tools.Normalize("solhint", res.Raw)
			out = append(out, convertExternal(fs, "solhint")...)
		}
	}
	if cfg.ExternalTools.Mythril && pctx != nil {
		// Best-effort: analyze first solidity file within budget
		var target string
		if len(pctx.SolidityFiles) > 0 {
			target = pctx.SolidityFiles[0]
		}
		if target != "" {
			ctxMyth, cancelM := context.WithTimeout(ctx, per)
			res := tools.RunWithTimeout(ctxMyth, "myth", "analyze", target, "-o", "json")
			cancelM()
			if res.Err == nil {
				fs, _ := tools.Normalize("myth", res.Raw)
				out = append(out, convertExternal(fs, "myth")...)
			}
		}
	}
	if cfg.ExternalTools.Gosec {
		ctxGosec, cancelG := context.WithTimeout(ctx, per)
		res := tools.RunWithTimeout(ctxGosec, "gosec", "-fmt=json", "./...")
		cancelG()
		if res.Err == nil {
			fs, _ := tools.Normalize("gosec", res.Raw)
			out = append(out, convertExternal(fs, "gosec")...)
		}
	}
	if cfg.ExternalTools.Govuln {
		ctxGV, cancelV := context.WithTimeout(ctx, per)
		res := tools.RunWithTimeout(ctxGV, "govulncheck", "-json", "./...")
		cancelV()
		if res.Err == nil {
			fs, _ := tools.Normalize("govulncheck", res.Raw)
			out = append(out, convertExternal(fs, "govulncheck")...)
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
