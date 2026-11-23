package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUsageAndVersion(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version code = %d, stderr = %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "dev" {
		t.Fatalf("version = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"pack"}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing args code = %d, stderr = %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"pack", "--not-a-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("bad flag code = %d, stderr = %s", code, stderr.String())
	}
}

func TestRunRequiresPasswordWithoutTerminal(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"pack", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "AIPACK_PASSWORD") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestResolvePasswordPrefersFlagThenEnv(t *testing.T) {
	t.Setenv("AIPACK_PASSWORD", "from-env")
	var stderr bytes.Buffer
	got, err := resolvePassword("from-flag", os.Stdin, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-flag" {
		t.Fatalf("password = %q", got)
	}
	if !strings.Contains(stderr.String(), "process list") {
		t.Fatalf("stderr = %s", stderr.String())
	}

	stderr.Reset()
	got, err = resolvePassword("", os.Stdin, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-env" {
		t.Fatalf("password = %q", got)
	}

	long := strings.Repeat("a", 1025)
	if _, err := resolvePassword(long, os.Stdin, &stderr); err == nil {
		t.Fatal("expected long password to fail")
	}
}

func TestRunPackUnpack(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "proj")
	if err := os.Mkdir(src, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hi"), 0o640); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "out.aipk")
	dest := filepath.Join(dir, "restored")
	t.Setenv("AIPACK_PASSWORD", "cli-secret")

	var stdout, stderr bytes.Buffer
	code := run([]string{"pack", src, "-o", archive, "-w", "1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("pack code = %d\n%s", code, stderr.String())
	}
	stderr.Reset()
	code = run([]string{"unpack", archive, "-o", dest}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unpack code = %d\n%s", code, stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hi" {
		t.Fatalf("body = %q", body)
	}
}
