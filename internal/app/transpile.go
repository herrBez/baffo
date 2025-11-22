package app

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/herrBez/baffo/internal/app/transpile"
)

var (
	idiomatic                     bool
	log_level                     string
	pipeline_threshold            int
	deal_with_error_locally       bool
	add_default_global_on_failure bool
	fidelity                      bool
	add_cleanup_processor         bool
	inline                        bool
)

func makeTranspileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "transpile [path ...]",
		Short:         "transpile a subset of Logstash to Ingest Pipeline",
		RunE:          runTranspile,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			/* Idiomatic is mutually exclusive with the other flags */
			if idiomatic {
				if pipeline_threshold != 1 {
					return fmt.Errorf("--idiomatic and --pipeline_threshold canno be specified together")
				}
				if !fidelity {
					return fmt.Errorf("--idiomatic and --fidelity cannot be specified together")
				}
				if !deal_with_error_locally {
					return fmt.Errorf("--idiomatic and --deal_with_error_locally cannot be specified together")
				}
				if add_default_global_on_failure {
					return fmt.Errorf("--idiomatic and --add_default_global_on_failure cannot be specified together")
				}
			}

			switch log_level {
			case "debug", "info", "warn", "warning", "error":
			default:
				return fmt.Errorf("invalid log_level: %s", log_level)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&idiomatic, "idiomatic", false, "whether to use idiomatic constructs in the transpiled output")
	cmd.Flags().IntVar(&pipeline_threshold, "pipeline_threshold", 1, "determine how many processors will cause the creation of a new pipeline in conditions")
	cmd.Flags().StringVar(&log_level, "log_level", "info", "determine the log_level")
	cmd.Flags().BoolVar(&deal_with_error_locally, "deal_with_error_locally", true, "whether we deal with errors locally, e.g., add tag on error by default")
	cmd.Flags().BoolVar(&add_default_global_on_failure, "add_default_global_on_failure", false, "whether to add a default global on failure")
	cmd.Flags().BoolVar(&fidelity, "fidelity", true, "try to keep correct if-else semantic")
	cmd.Flags().BoolVar(&add_cleanup_processor, "add_cleanup_processor", true, "add a cleanup processor to remove temporary fields created by the transpiler")
	cmd.Flags().BoolVar(&inline, "inline", false, "whether the input is provided inline or via file paths(default false)")
	return cmd
}

func runTranspile(cmd *cobra.Command, args []string) error {
	check := transpile.New(pipeline_threshold, log_level, deal_with_error_locally, add_default_global_on_failure, fidelity, add_cleanup_processor, inline)
	return check.Run(args)
}
