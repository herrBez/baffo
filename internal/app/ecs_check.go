package app

import (
	"github.com/spf13/cobra"

	"github.com/herrBez/baffo/internal/app/ecs_check"
)

func makeECSCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "ecs_check [path ...]",
		Short:         "identify ecs_compatibility problems",
		RunE:          runECSCheck,
		SilenceErrors: true,
	}

	return cmd
}

func runECSCheck(cmd *cobra.Command, args []string) error {
	check := ecs_check.New()
	return check.Run(args)
}
