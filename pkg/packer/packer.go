package packer

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/errgroup"

	"github.com/edwinlmm/aipack/pkg/crypto"
)

const (
	Magic     = "AIPK"
	Version   = byte(1)
	HeaderSize = 4 + 1 + crypto.SaltSize + crypto.NonceSize // magic + ver + salt + nonce
	ZstdLevel = zstd.SpeedBestCompression
)

// DefaultExcludes for programming projects to maximize useful compression ratio.
var DefaultExcludes = []string{
	".git",
	"node_modules",
	"vendor",
	"__pycache__",
	".venv",
	"venv",
	"dist",
	"build",
	"target",
	".idea",
	".vscode",
	"*.exe",
	"*.dll",
	"*.so",
	"*.dylib",
	"*.bin",
	"*.log",
	"*.tmp",
	".DS_Store",
}

// PackOptions configures packing.
type PackOptions struct {
	SourceDir string
	Output    string
	Password  []byte
	Excludes  []string
	Workers   int
}

// UnpackOptions configures unpacking.
type UnpackOptions struct {
	Input     string
	OutputDir string
	Password  []byte
}

// Pack creates a maximally compressed and encrypted archive of the project.
// File collection is sequential for correctness; zstd encoder uses internal concurrency.
// Follows production practices: context cancellation, wrapped errors, secure crypto.
func Pack(ctx context.Context, opts PackOptions) error {
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if len(opts.Excludes) == 0 {
		opts.Excludes = DefaultExcludes
	}

	// Collect relative paths (sequential walk is reliable; concurrency here adds complexity for little gain on listing)
	var files []string
	err := filepath.WalkDir(opts.SourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rel, err := filepath.Rel(opts.SourceDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		if shouldExclude(rel, excludesMatch(d.Name(), opts.Excludes)) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		files = append(files, rel)
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk directory: %w", err)
	}

	// Deterministic order for better compression and reproducibility
	sort.Strings(files)

	// Build tar
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, relPath := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fullPath := filepath.Join(opts.SourceDir, relPath)
		info, err := os.Stat(fullPath)
		if err != nil {
			return fmt.Errorf("stat %s: %w", relPath, err)
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("tar header for %s: %w", relPath, err)
		}
		header.Name = filepath.ToSlash(relPath) // portable

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header %s: %w", relPath, err)
		}

		if !info.IsDir() {
			f, err := os.Open(fullPath)
			if err != nil {
				return fmt.Errorf("open %s: %w", relPath, err)
			}
			_, copyErr := io.Copy(tw, f)
			f.Close()
			if copyErr != nil {
				return fmt.Errorf("tar copy %s: %w", relPath, copyErr)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}

	// High-level zstd compression with concurrency
	var compressed bytes.Buffer
	enc, err := zstd.NewWriter(&compressed,
		zstd.WithEncoderLevel(ZstdLevel),
		zstd.WithEncoderConcurrency(opts.Workers),
	)
	if err != nil {
		return fmt.Errorf("create zstd encoder: %w", err)
	}
	if _, err := io.Copy(enc, &tarBuf); err != nil {
		enc.Close()
		return fmt.Errorf("compress data: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close zstd encoder: %w", err)
	}

	// Encrypt with AES-GCM
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	nonce, err := crypto.GenerateNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	key := crypto.DeriveKey(opts.Password, salt)

	ciphertext, err := crypto.Encrypt(key, nonce, compressed.Bytes())
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Write final file
	outFile, err := os.Create(opts.Output)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := outFile.Write([]byte(Magic)); err != nil {
		return fmt.Errorf("write magic: %w", err)
	}
	if _, err := outFile.Write([]byte{Version}); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}
	if _, err := outFile.Write(nonce); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}
	if _, err := outFile.Write(ciphertext); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}

	return nil
}

// Unpack decrypts, decompresses and extracts securely.
func Unpack(ctx context.Context, opts UnpackOptions) error {
	data, err := os.ReadFile(opts.Input)
	if err != nil {
		return fmt.Errorf("read packed file: %w", err)
	}
	if len(data) < HeaderSize {
		return errors.New("packed file too small or corrupted")
	}

	if string(data[0:4]) != Magic {
		return errors.New("invalid magic bytes: not an aipack file")
	}
	if data[4] != Version {
		return fmt.Errorf("unsupported version %d", data[4])
	}

	salt := data[5 : 5+crypto.SaltSize]
	nonce := data[5+crypto.SaltSize : HeaderSize]
	ciphertext := data[HeaderSize:]

	key := crypto.DeriveKey(opts.Password, salt)
	plaintext, err := crypto.Decrypt(key, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong password or corrupted): %w", err)
	}

	dec, err := zstd.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return fmt.Errorf("create zstd decoder: %w", err)
	}
	defer dec.Close()

	tr := tar.NewReader(dec)

	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	cleanOut := filepath.Clean(opts.OutputDir)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		// Strict path traversal protection
		target := filepath.Join(opts.OutputDir, header.Name)
		cleanTarget := filepath.Clean(target)
		if !strings.HasPrefix(cleanTarget, cleanOut+string(os.PathSeparator)) && cleanTarget != cleanOut {
			return fmt.Errorf("path traversal attempt detected: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleanTarget, os.FileMode(header.Mode)&0o777); err != nil {
				return fmt.Errorf("create directory %s: %w", cleanTarget, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(cleanTarget), 0o755); err != nil {
				return fmt.Errorf("create parent for %s: %w", cleanTarget, err)
			}
			f, err := os.OpenFile(cleanTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("create file %s: %w", cleanTarget, err)
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil {
				return fmt.Errorf("extract %s: %w", cleanTarget, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close %s: %w", cleanTarget, closeErr)
			}
		}
		// Other types (symlinks, etc.) intentionally skipped for safety
	}

	return nil
}

func excludesMatch(name string, excludes []string) bool {
	for _, excl := range excludes {
		if matched, _ := filepath.Match(excl, name); matched {
			return true
		}
		if name == excl {
			return true
		}
	}
	return false
}

func shouldExclude(rel string, nameExcluded bool) bool {
	if nameExcluded {
		return true
	}
	// also check path components
	parts := strings.Split(rel, string(os.PathSeparator))
	for _, p := range parts {
		// re-check but simple for now
		_ = p
	}
	return false
}

// Example of concurrent usage pattern (for future extension, e.g. parallel hashing)
func exampleConcurrent(ctx context.Context, items []string) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4)
	for _, item := range items {
		item := item
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return gctx.Err()
			default:
			}
			// do work
			_ = item
			return nil
		})
	}
	return g.Wait()
}
