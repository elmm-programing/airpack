package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/edwinlmm/aipack/pkg/packer"
)

var unpackCmd = &cobra.Command{
	Use:   "unpack <packed-file>",
	Short: "Decrypt and decompress a packed project",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]
		outputDir, _ := cmd.Flags().GetString("output")
		passwordFlag, _ := cmd.Flags().GetString("password")

		if outputDir == "" {
			outputDir = "unpacked"
		}

		password, err := getPassword(passwordFlag, "Enter password: ")
		if err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		opts := packer.UnpackOptions{
			Input:     input,
			OutputDir: outputDir,
			Password:  password,
		}

		fmt.Fprintf(os.Stderr, "Unpacking %s → %s...\n", input, outputDir)
		if err := packer.Unpack(ctx, opts); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Done. Project ready to open in Cursor / feed to AI.\n")
		return nil
	},
}

func init() {
	unpackCmd.Flags().StringP("output", "o", "", "output directory (default: unpacked)")
	unpackCmd.Flags().StringP("password", "p", "", "password (prompted if empty)")
}
