package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/edwinlmm/aipack/pkg/crypto"
	"github.com/edwinlmm/aipack/pkg/packer"
)

func newUnpackCmd() *cobra.Command {
	var (
		output   string
		password string
		workers  int
		maxBytes int64
	)

	command := &cobra.Command{
		Use:           "unpack <packed-file>",
		Short:         "Decrypt and extract a packed project",
		Args:          exactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if workers < 0 {
				return usageErr(fmt.Errorf("workers must be zero or positive"))
			}
			if maxBytes < 0 {
				return usageErr(fmt.Errorf("max-bytes must be zero or positive"))
			}
			pw, err := resolvePassword(password, os.Stdin, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer crypto.Wipe(pw)

			out := output
			if out == "" {
				out = "unpacked"
			}

			ctx, stop := signalContext(cmd)
			defer stop()

			fmt.Fprintf(cmd.ErrOrStderr(), "Unpacking %s → %s\n", args[0], out)
			res, err := packer.Unpack(ctx, packer.UnpackOptions{
				Input:     args[0],
				OutputDir: out,
				Password:  pw,
				Workers:   workers,
				MaxBytes:  maxBytes,
			})
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return fmt.Errorf("interrupted: %w", err)
				}
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Done. %d files, %d directories.\n", res.Files, res.Dirs)
			return nil
		},
	}

	command.Flags().StringVarP(&output, "output", "o", "", "output directory (default: unpacked)")
	command.Flags().StringVarP(&password, "password", "p", "", "password (visible in the process list; prefer AIPACK_PASSWORD)")
	command.Flags().IntVarP(&workers, "workers", "w", 0, "zstd worker limit (0 uses GOMAXPROCS, capped at 8)")
	command.Flags().Int64Var(&maxBytes, "max-bytes", packer.DefaultMaxBytes, "maximum extracted size in bytes")
	return command
}
