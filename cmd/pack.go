package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/edwinlmm/aipack/pkg/packer"
)

var packCmd = &cobra.Command{
	Use:   "pack <source-dir>",
	Short: "Compress and encrypt a project directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]
		output, _ := cmd.Flags().GetString("output")
		passwordFlag, _ := cmd.Flags().GetString("password")
		workers, _ := cmd.Flags().GetInt("workers")

		if output == "" {
			output = source + ".aipk"
		}

		password, err := getPassword(passwordFlag, "Enter password: ")
		if err != nil {
			return err
		}
		if len(password) == 0 {
			return fmt.Errorf("password cannot be empty")
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		opts := packer.PackOptions{
			SourceDir: source,
			Output:    output,
			Password:  password,
			Workers:   workers,
		}

		fmt.Fprintf(os.Stderr, "Packing %s → %s (workers=%d)...\n", source, output, workers)
		if err := packer.Pack(ctx, opts); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Done. File ready for secure transfer.\n")
		return nil
	},
}

func init() {
	packCmd.Flags().StringP("output", "o", "", "output file (default: <dir>.aipk)")
	packCmd.Flags().StringP("password", "p", "", "password (prompted if empty; prefer env or prompt)")
	packCmd.Flags().IntP("workers", "w", 4, "concurrency for zstd encoder")
}

func getPassword(flagVal, prompt string) ([]byte, error) {
	if flagVal != "" {
		return []byte(flagVal), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}
