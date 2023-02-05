package app

import (
	"github.com/spf13/cobra"

	"github.com/breml/logstash-config/internal/app/transpile"
)

func makeTranspileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "transpile [path ...]",
		Short:         "identify ecs_compatibility problems",
		RunE:          runTranspile,
		SilenceErrors: true,
	}

	return cmd
}

func runTranspile(cmd *cobra.Command, args []string) error {
	check := transpile.New()
	return check.Run(args)
}
