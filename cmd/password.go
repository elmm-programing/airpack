package cmd

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/edwinlmm/aipack/pkg/crypto"
	"github.com/edwinlmm/aipack/pkg/packer"
)

const envPassword = "AIPACK_PASSWORD"

// resolvePassword chooses a password from the flag, then the environment,
// then a terminal prompt. Flag and environment values are copied into a
// fresh slice the caller can wipe.
func resolvePassword(flagVal string, stdin *os.File, stderr io.Writer) ([]byte, error) {
	if flagVal != "" {
		fmt.Fprintln(stderr, "warning: -p exposes the password in the process list; prefer AIPACK_PASSWORD or the prompt")
		return copyPassword(flagVal)
	}
	if env := os.Getenv(envPassword); env != "" {
		return copyPassword(env)
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		return nil, fmt.Errorf("password required: set %s or run in a terminal", envPassword)
	}
	fmt.Fprint(stderr, "Enter password: ")
	pw, err := term.ReadPassword(int(stdin.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(pw) == 0 {
		return nil, packer.ErrEmptyPassword
	}
	if len(pw) > packer.MaxPasswordLen {
		crypto.Wipe(pw)
		return nil, packer.ErrPasswordTooLong
	}
	return pw, nil
}

func copyPassword(s string) ([]byte, error) {
	if len(s) > packer.MaxPasswordLen {
		return nil, packer.ErrPasswordTooLong
	}
	return []byte(s), nil
}
