package packer

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"go.uber.org/goleak"

	"github.com/edwinlmm/aipack/pkg/crypto"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestExcluded(t *testing.T) {
	t.Parallel()
	patterns := DefaultExcludes()
	patterns[0] = "mutated"
	if DefaultExcludes()[0] == "mutated" {
		t.Fatal("DefaultExcludes returned a shared slice")
	}
	tests := []struct {
		name    string
		rel     string
		want    bool
		pattern []string
	}{
		{name: "nested node_modules", rel: "web/node_modules/leftpad/index.js", want: true, pattern: DefaultExcludes()},
		{name: "log in subdirectory", rel: "pkg/debug.log", want: true, pattern: DefaultExcludes()},
		{name: "source file", rel: "pkg/debug.go", want: false, pattern: DefaultExcludes()},
		{name: "name contains exclude text", rel: "src/node_modules_tools/main.go", want: false, pattern: DefaultExcludes()},
		{name: "full path glob", rel: "gen/out.txt", want: true, pattern: []string{"gen/*.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := excluded(tt.rel, tt.pattern); got != tt.want {
				t.Fatalf("excluded(%q) = %v, want %v", tt.rel, got, tt.want)
			}
		})
	}
}

func TestSafeArchivePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "relative file", in: "src/main.go"},
		{name: "cleans dot segments", in: "src/./main.go"},
		{name: "parent traversal", in: "../secret", wantErr: true},
		{name: "nested traversal", in: "src/../../secret", wantErr: true},
		{name: "absolute", in: "/etc/passwd", wantErr: true},
		{name: "windows traversal", in: `..\..\secret`, wantErr: true},
		{name: "nul", in: "ok\x00hidden", wantErr: true},
		{name: "dot", in: "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := safeArchivePath(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrUnsafePath) {
					t.Fatalf("error = %v, want unsafe path", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(got, "..") {
				t.Fatalf("accepted %q", got)
			}
		})
	}
}

func FuzzSafeArchivePath(f *testing.F) {
	f.Add("src/main.go")
	f.Add("../etc/passwd")
	f.Add("/etc/passwd")
	f.Add(`..\..\windows`)
	f.Add("foo/../../x")
	f.Fuzz(func(t *testing.T, name string) {
		got, err := safeArchivePath(name)
		if err != nil {
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if got != "." && !filepath.IsLocal(got) {
			t.Fatalf("accepted non-local path %q from %q", got, name)
		}
	})
}

func TestPackUnpackRoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	src := filepath.Join(root, "proj")
	mustMkdir(t, src)
	mustWrite(t, filepath.Join(src, "main.go"), "package main\n")
	mustMkdir(t, filepath.Join(src, "nested"))
	mustWrite(t, filepath.Join(src, "nested", "note.txt"), "hello")
	mustMkdir(t, filepath.Join(src, "nested", "node_modules"))
	mustWrite(t, filepath.Join(src, "nested", "node_modules", "secret.js"), "nope")
	mustWrite(t, filepath.Join(src, "debug.log"), "noise")
	outside := filepath.Join(root, "secret.txt")
	mustWrite(t, outside, "TOP-SECRET")
	if err := os.Symlink(outside, filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(root, "proj.aipk")
	res, err := Pack(context.Background(), testPack(src, archive))
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || res.SkippedSymlinks != 1 {
		t.Fatalf("result = %+v, want 2 files and 1 skipped symlink", res)
	}

	dest := filepath.Join(root, "out")
	if _, err := Unpack(context.Background(), testUnpack(archive, dest)); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, filepath.Join(dest, "main.go")); got != "package main\n" {
		t.Fatalf("main.go = %q", got)
	}
	if got := mustRead(t, filepath.Join(dest, "nested", "note.txt")); got != "hello" {
		t.Fatalf("note = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "nested", "node_modules", "secret.js")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("excluded file exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "debug.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("log exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "link")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink was archived: %v", err)
	}
}

func TestPackRejectsEmptyPasswordCanceledContextAndSize(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	src := filepath.Join(root, "proj")
	mustMkdir(t, src)
	mustWrite(t, filepath.Join(src, "a.txt"), "abcdef")

	opts := testPack(src, filepath.Join(root, "out.aipk"))
	opts.Password = nil
	if _, err := Pack(context.Background(), opts); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty password error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Pack(ctx, testPack(src, filepath.Join(root, "out.aipk"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}

	limited := testPack(src, filepath.Join(root, "big.aipk"))
	limited.MaxBytes = 3
	if _, err := Pack(context.Background(), limited); !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("size error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "big.aipk")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("size failure left an output file")
	}
}

func TestUnpackRejectsWrongPasswordAndTamper(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	src := filepath.Join(root, "proj")
	mustMkdir(t, src)
	mustWrite(t, filepath.Join(src, "a.txt"), "alpha")
	archive := filepath.Join(root, "ok.aipk")
	if _, err := Pack(context.Background(), testPack(src, archive)); err != nil {
		t.Fatal(err)
	}

	bad := testUnpack(archive, filepath.Join(root, "bad"))
	bad.Password = []byte("wrong-password")
	if _, err := Unpack(context.Background(), bad); !errors.Is(err, crypto.ErrAuthentication) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "bad")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed unpack published a directory")
	}

	blob, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xff
	tampered := filepath.Join(root, "tampered.aipk")
	if err := os.WriteFile(tampered, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(context.Background(), testUnpack(tampered, filepath.Join(root, "tampered-out"))); !errors.Is(err, crypto.ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestExtractRejectsTraversalAndSpecialFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dest := filepath.Join(root, "out")
	mustMkdir(t, dest)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("evil")
	for _, name := range []string{"../evil.txt", "/tmp/evil.txt", "nested/../../evil.txt"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := extractTar(context.Background(), &buf, dest, 1<<20); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("extract error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "evil.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("traversal wrote a sibling file")
	}
}

func TestExtractRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dest := filepath.Join(root, "out")
	outside := filepath.Join(root, "outside")
	mustMkdir(t, dest)
	mustMkdir(t, outside)
	if err := os.Symlink(outside, filepath.Join(dest, "escape")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("pwned")
	if err := tw.WriteHeader(&tar.Header{Name: "escape/pwned.txt", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := extractTar(context.Background(), &buf, dest, 1<<20); err == nil {
		t.Fatal("expected symlink escape to fail")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrote through a symlink outside the output root")
	}
}

func TestUnpackV1(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	body := []byte("legacy")
	if err := tw.WriteHeader(&tar.Header{Name: "old.txt", Mode: 0o640, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	enc, err := zstd.NewWriter(&compressed, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}

	password := []byte("v1-password")
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := crypto.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	// Version 1 does not store KDF parameters, so the reader always uses DefaultKDF.
	key, err := crypto.DeriveKey(password, salt, crypto.DefaultKDF)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Wipe(key)
	sealed, err := crypto.Encrypt(key, nonce, compressed.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var blob bytes.Buffer
	blob.WriteString(magic)
	blob.WriteByte(versionV1)
	blob.Write(salt)
	blob.Write(nonce)
	blob.Write(sealed)

	dest := filepath.Join(root, "out")
	mustMkdir(t, dest)
	res, err := decryptExtract(context.Background(), &blob, dest, UnpackOptions{
		MaxBytes: 1 << 20,
		Workers:  1,
	}, password)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 {
		t.Fatalf("files = %d", res.Files)
	}
	if got := mustRead(t, filepath.Join(dest, "old.txt")); got != "legacy" {
		t.Fatalf("old.txt = %q", got)
	}
}

func TestPackSkipsExistingOutputInsideSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	archive := filepath.Join(root, "proj.aipk")
	mustWrite(t, archive, "OLD-ARCHIVE")
	opts := testPack(root, archive)
	opts.Excludes = []string{}
	if _, err := Pack(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "restored")
	if _, err := Unpack(context.Background(), testUnpack(archive, dest)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "proj.aipk")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("archive included its own previous output")
	}
}

func testPack(src, out string) PackOptions {
	return PackOptions{
		SourceDir: src,
		Output:    out,
		Password:  []byte("test-password"),
		MaxBytes:  1 << 20,
		Workers:   1,
		Level:     zstd.SpeedFastest,
		KDF:       crypto.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1},
	}
}

func testUnpack(in, out string) UnpackOptions {
	return UnpackOptions{
		Input:     in,
		OutputDir: out,
		Password:  []byte("test-password"),
		MaxBytes:  1 << 20,
		Workers:   1,
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
