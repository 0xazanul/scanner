package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/xab-mack/smartscanner/internal/engine"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/report"
	"github.com/xab-mack/smartscanner/internal/tui"
)

func AddCommands(root *cobra.Command) {
	root.AddCommand(newScanCmd())
	root.AddCommand(newInitCmd())
	root.AddCommand(newRulesCmd())
}

func newScanCmd() *cobra.Command {
	var (
		path          string
		format        string
		budgetMs      int
		failOn        string
		outputFile    string
		sarifOut      string
		deltaOnly     bool
		useTUI        bool
		writeBaseline string
	)
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a project or repository for vulnerabilities",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				path = args[0]
			}
			if path == "" {
				path = "."
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(budgetMs)*time.Millisecond)
			defer cancel()

			eng := engine.New()
			result, err := eng.Scan(ctx, model.ScanRequest{Path: path, DeltaOnly: deltaOnly, TimeBudget: time.Duration(budgetMs) * time.Millisecond})
			if err != nil {
				return err
			}

			if useTUI {
				// TUI mode ignores format flags
				// Note: currently minimal; future: narration and tree
				return tui.Run(result.Findings)
			}
			switch format {
			case "json":
				data, _ := json.MarshalIndent(result, "", "  ")
				if outputFile != "" {
					return os.WriteFile(outputFile, data, 0o644)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
			case "sarif":
				data, _ := report.ToSARIF(result.Findings)
				if sarifOut != "" {
					return os.WriteFile(sarifOut, data, 0o644)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
			default:
				// minimal human output for now
				fmt.Fprintf(cmd.OutOrStdout(), "Findings: %d (elapsed %s)\n", len(result.Findings), result.Elapsed)
				for _, f := range result.Findings {
					fmt.Fprintf(cmd.OutOrStdout(), "- %s [%s] %s:%d-%d %s (conf=%.2f)\n", f.RuleID, f.Severity, f.File, f.StartLine, f.EndLine, f.Message, f.Confidence)
				}
			}

			// simple fail-on behavior
			if failOn != "" {
				threshold := model.ParseSeverity(failOn)
				for _, f := range result.Findings {
					if model.SeverityGTE(f.Severity, threshold) {
						return fmt.Errorf("fail-on threshold met: %s", f.Severity)
					}
				}
			}
			if writeBaseline != "" {
				return engine.WriteBaseline(writeBaseline, result.Findings)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table|json|sarif")
	cmd.Flags().IntVar(&budgetMs, "budget-ms", 4500, "Time budget for the scan in milliseconds")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Fail if a finding of severity or higher is found (low|medium|high|critical)")
	cmd.Flags().StringVarP(&outputFile, "out", "o", "", "Write report to file (with --format json)")
	cmd.Flags().StringVar(&sarifOut, "sarif-out", "", "Write SARIF report to file (with --format sarif)")
	cmd.Flags().BoolVar(&deltaOnly, "delta", false, "Analyze only changed files (delta scan)")
	cmd.Flags().BoolVar(&useTUI, "tui", false, "Render interactive TUI output")
	cmd.Flags().StringVar(&writeBaseline, "write-baseline", "", "Write a baseline file with finding fingerprints")
	return cmd
}
