// Package packer packs a project tree into an encrypted archive and unpacks it again.
//
// The on-disk format is version 2: a header (magic, KDF parameters, salt, nonce
// prefix) followed by framed AES-256-GCM chunks of a zstd-compressed tar stream.
// Version 1 archives (single GCM blob) can still be unpacked.
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
	"runtime"
	"sort"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/errgroup"

	"github.com/edwinlmm/aipack/pkg/crypto"
)

const (
	// DefaultMaxBytes is the maximum source size pack will accept and the
	// maximum number of bytes unpack will write.
	DefaultMaxBytes int64 = 8 << 30
	// MaxPasswordLen bounds Argon2id input so a huge password cannot pin memory.
	MaxPasswordLen = 1024
	maxWorkers     = 8
)

var (
	// ErrEmptyPassword is returned when the password is missing.
	ErrEmptyPassword = errors.New("packer: password is empty")
	// ErrPasswordTooLong is returned when the password exceeds MaxPasswordLen.
	ErrPasswordTooLong = errors.New("packer: password is too long")
	// ErrUnsafePath is returned when a path escapes a root or uses a rejected entry type.
	ErrUnsafePath = errors.New("packer: unsafe path")
	// ErrBadArchive is returned when the archive bytes are not a valid aipack file.
	ErrBadArchive = errors.New("packer: invalid archive")
	// ErrSizeLimit is returned when a configured byte or entry limit is exceeded.
	ErrSizeLimit = errors.New("packer: size limit exceeded")
	// ErrUnsupported is returned for an archive version this binary cannot read.
	ErrUnsupported = errors.New("packer: unsupported archive version")
	// ErrOutputExists is returned when the unpack destination is not an empty directory.
	ErrOutputExists = errors.New("packer: output directory is not empty")
)

// PackOptions configures Pack.
// A nil Excludes slice selects DefaultExcludes. A non-nil empty slice disables excludes.
// The zero KDF value selects crypto.DefaultKDF. The zero Level selects best compression.
type PackOptions struct {
	SourceDir string
	Output    string
	Password  []byte
	Excludes  []string
	Workers   int
	MaxBytes  int64
	KDF       crypto.KDFParams
	Level     zstd.EncoderLevel
}

// UnpackOptions configures Unpack.
// KDF parameters come from the archive header and are rejected when they
// exceed the production limits.
type UnpackOptions struct {
	Input     string
	OutputDir string
	Password  []byte
	Workers   int
	MaxBytes  int64
}

// Result counts what a pack or unpack call did.
type Result struct {
	Files           int
	Dirs            int
	SkippedSymlinks int
	SkippedSpecial  int
	Bytes           int64
}

type treeEntry struct {
	rel   string
	isDir bool
	size  int64
}

// Pack writes an encrypted archive of opts.SourceDir to opts.Output.
// The tar stream, zstd encoder, and chunk encryptor run as one pipeline:
// file bytes are not buffered as a single archive image.
// Two goroutines (tar producer and compress/encrypt consumer) share an
// io.Pipe. errgroup cancels the sibling when either fails, and both pipe
// ends are closed so neither side blocks after the other returns.
func Pack(ctx context.Context, opts PackOptions) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	norm, err := normalizePack(opts)
	if err != nil {
		return Result{}, err
	}
	entries, res, err := collect(ctx, norm)
	if err != nil {
		return Result{}, err
	}
	if res.Bytes > norm.MaxBytes {
		return Result{}, fmt.Errorf("%w: source is %d bytes", ErrSizeLimit, res.Bytes)
	}

	outAbs, err := filepath.Abs(norm.Output)
	if err != nil {
		return Result{}, fmt.Errorf("resolve output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outAbs), dirPerm); err != nil {
		return Result{}, fmt.Errorf("create output directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(outAbs), ".aipack-*")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary archive: %w", err)
	}
	closed := false
	committed := false
	defer func() {
		if !closed {
			tmp.Close()
		}
		if !committed {
			os.Remove(tmp.Name())
		}
	}()

	// Password bytes are cloned so wiping them does not race the caller.
	// The clone is wiped after both pipeline goroutines have returned.
	password := append([]byte(nil), norm.Password...)
	defer crypto.Wipe(password)

	pr, pw := io.Pipe()
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		err := writeTar(gctx, pw, norm.SourceDir, entries)
		if err != nil {
			_ = pw.CloseWithError(err)
			return err
		}
		if err := pw.Close(); err != nil {
			return fmt.Errorf("close archive pipe: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		defer pr.Close()
		return compressEncrypt(gctx, pr, tmp, norm, password)
	})
	if err := g.Wait(); err != nil {
		return Result{}, err
	}
	if err := tmp.Sync(); err != nil {
		return Result{}, fmt.Errorf("sync archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Result{}, fmt.Errorf("close archive: %w", err)
	}
	closed = true
	if err := os.Rename(tmp.Name(), outAbs); err != nil {
		return Result{}, fmt.Errorf("rename archive: %w", err)
	}
	committed = true
	return res, nil
}

// Unpack decrypts opts.Input and extracts it under opts.OutputDir.
// Extraction goes to a private temporary directory first. The destination
// is replaced only after the archive authenticates and extracts completely,
// so a truncated or forged archive does not leave a partial tree behind.
func Unpack(ctx context.Context, opts UnpackOptions) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	norm, err := normalizeUnpack(opts)
	if err != nil {
		return Result{}, err
	}
	if err := ensureOutputAvailable(norm.OutputDir); err != nil {
		return Result{}, err
	}

	f, err := os.Open(norm.Input)
	if err != nil {
		return Result{}, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	parent := filepath.Dir(norm.OutputDir)
	if err := os.MkdirAll(parent, dirPerm); err != nil {
		return Result{}, fmt.Errorf("create output parent: %w", err)
	}
	tmpDir, err := os.MkdirTemp(parent, ".aipack-unpack-*")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmpDir)
		}
	}()

	password := append([]byte(nil), norm.Password...)
	defer crypto.Wipe(password)

	res, err := decryptExtract(ctx, f, tmpDir, norm, password)
	if err != nil {
		return Result{}, err
	}
	if err := publishDir(tmpDir, norm.OutputDir); err != nil {
		return Result{}, err
	}
	committed = true
	return res, nil
}

func normalizePack(opts PackOptions) (PackOptions, error) {
	if err := validatePassword(opts.Password); err != nil {
		return PackOptions{}, err
	}
	if opts.SourceDir == "" {
		return PackOptions{}, fmt.Errorf("%w: empty source", ErrBadArchive)
	}
	info, err := os.Lstat(opts.SourceDir)
	if err != nil {
		return PackOptions{}, fmt.Errorf("stat source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return PackOptions{}, fmt.Errorf("%w: source is a symlink", ErrUnsafePath)
	}
	if !info.IsDir() {
		return PackOptions{}, fmt.Errorf("%w: source is not a directory", ErrUnsafePath)
	}
	if opts.Output == "" {
		opts.Output = opts.SourceDir + ".aipk"
	}
	srcAbs, err := filepath.Abs(opts.SourceDir)
	if err != nil {
		return PackOptions{}, fmt.Errorf("resolve source: %w", err)
	}
	outAbs, err := filepath.Abs(opts.Output)
	if err != nil {
		return PackOptions{}, fmt.Errorf("resolve output: %w", err)
	}
	if srcAbs == outAbs {
		return PackOptions{}, fmt.Errorf("%w: output is the source directory", ErrUnsafePath)
	}
	opts.SourceDir = srcAbs
	opts.Output = outAbs
	if opts.Excludes == nil {
		opts.Excludes = DefaultExcludes()
	}
	if err := validateExcludes(opts.Excludes); err != nil {
		return PackOptions{}, err
	}
	opts.Workers = normalizeWorkers(opts.Workers)
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	params, err := opts.KDF.OrDefault()
	if err != nil {
		return PackOptions{}, err
	}
	opts.KDF = params
	if opts.Level == 0 {
		opts.Level = zstd.SpeedBestCompression
	}
	return opts, nil
}

func normalizeUnpack(opts UnpackOptions) (UnpackOptions, error) {
	if err := validatePassword(opts.Password); err != nil {
		return UnpackOptions{}, err
	}
	if opts.Input == "" {
		return UnpackOptions{}, fmt.Errorf("%w: empty input", ErrBadArchive)
	}
	if opts.OutputDir == "" {
		opts.OutputDir = "unpacked"
	}
	outAbs, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return UnpackOptions{}, fmt.Errorf("resolve output: %w", err)
	}
	opts.OutputDir = outAbs
	opts.Workers = normalizeWorkers(opts.Workers)
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	return opts, nil
}

func validatePassword(password []byte) error {
	if len(password) == 0 {
		return ErrEmptyPassword
	}
	if len(password) > MaxPasswordLen {
		return ErrPasswordTooLong
	}
	return nil
}

func normalizeWorkers(n int) int {
	if n <= 0 {
		n = runtime.GOMAXPROCS(0)
	}
	if n > maxWorkers {
		n = maxWorkers
	}
	procs := runtime.GOMAXPROCS(0)
	if procs > 0 && n > procs {
		n = procs
	}
	if n < 1 {
		return 1
	}
	return n
}

func collect(ctx context.Context, opts PackOptions) ([]treeEntry, Result, error) {
	var entries []treeEntry
	var res Result
	err := filepath.WalkDir(opts.SourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(opts.SourceDir, path)
		if err != nil {
			return fmt.Errorf("relative path %s: %w", path, err)
		}
		if rel == "." {
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", rel, err)
		}
		if abs == opts.Output {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			res.SkippedSymlinks++
			return nil
		}
		if excluded(rel, opts.Excludes) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			entries = append(entries, treeEntry{rel: rel, isDir: true})
			res.Dirs++
			return nil
		}
		if !info.Mode().IsRegular() {
			res.SkippedSpecial++
			return nil
		}
		if info.Size() < 0 || res.Bytes > opts.MaxBytes-info.Size() {
			return fmt.Errorf("%w: source exceeds limit", ErrSizeLimit)
		}
		res.Bytes += info.Size()
		res.Files++
		entries = append(entries, treeEntry{rel: rel, size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, Result{}, fmt.Errorf("walk source: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rel < entries[j].rel
	})
	return entries, res, nil
}

func writeTar(ctx context.Context, w io.Writer, source string, entries []treeEntry) error {
	tw := tar.NewWriter(w)
	for _, ent := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		full := filepath.Join(source, ent.rel)
		info, err := os.Lstat(full)
		if err != nil {
			return fmt.Errorf("stat %s: %w", ent.rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s became a symlink", ErrUnsafePath, ent.rel)
		}
		if ent.isDir {
			if !info.IsDir() {
				return fmt.Errorf("%w: %s is no longer a directory", ErrBadArchive, ent.rel)
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return fmt.Errorf("tar header %s: %w", ent.rel, err)
			}
			hdr.Name = filepath.ToSlash(ent.rel) + "/"
			hdr.Mode = int64(dirPerm)
			hdr.Format = tar.FormatPAX
			if err := tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("write tar header %s: %w", ent.rel, err)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is no longer a regular file", ErrUnsafePath, ent.rel)
		}
		if err := writeRegular(ctx, tw, full, ent.rel, info); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	return nil
}

func writeRegular(ctx context.Context, tw *tar.Writer, full, rel string, info os.FileInfo) (err error) {
	f, err := openNoFollow(full)
	if err != nil {
		return fmt.Errorf("open %s: %w", rel, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("close %s: %w", rel, cerr)
		}
	}()

	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("tar header %s: %w", rel, err)
	}
	hdr.Name = filepath.ToSlash(rel)
	hdr.Mode = int64(archivePerm(int64(info.Mode().Perm())))
	hdr.Format = tar.FormatPAX
	hdr.Size = info.Size()
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write tar header %s: %w", rel, err)
	}
	n, err := copyContext(ctx, tw, io.LimitReader(f, info.Size()))
	if err != nil {
		return fmt.Errorf("read %s: %w", rel, err)
	}
	if n != info.Size() {
		return fmt.Errorf("%w: %s changed size while packing", ErrBadArchive, rel)
	}
	return nil
}

func compressEncrypt(ctx context.Context, r io.Reader, dst *os.File, opts PackOptions, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	prefix, err := crypto.GenerateNoncePrefix()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	key, err := crypto.DeriveKey(password, salt, opts.KDF)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	defer crypto.Wipe(key)

	if err := writeV2Header(dst, opts.KDF, salt, prefix); err != nil {
		return err
	}
	cw, err := crypto.NewChunkWriter(dst, key, prefix, versionV2)
	if err != nil {
		return fmt.Errorf("create encryptor: %w", err)
	}
	enc, err := zstd.NewWriter(cw,
		zstd.WithEncoderLevel(opts.Level),
		zstd.WithEncoderConcurrency(opts.Workers),
		zstd.WithWindowSize(windowSize),
	)
	if err != nil {
		return fmt.Errorf("create zstd encoder: %w", err)
	}
	encoderClosed := false
	defer func() {
		if !encoderClosed {
			// Close waits for zstd's worker goroutines.
			_ = enc.Close()
		}
	}()
	if _, err := copyContext(ctx, enc, r); err != nil {
		return fmt.Errorf("compress: %w", err)
	}
	if err := enc.Close(); err != nil {
		encoderClosed = true
		return fmt.Errorf("finish compression: %w", err)
	}
	encoderClosed = true
	if err := cw.Close(); err != nil {
		return fmt.Errorf("finish encryption: %w", err)
	}
	return nil
}

func decryptExtract(ctx context.Context, r io.Reader, dest string, opts UnpackOptions, password []byte) (Result, error) {
	pre, err := readPreamble(r)
	if err != nil {
		return Result{}, err
	}
	key, err := crypto.DeriveKey(password, pre.salt, pre.params)
	if err != nil {
		return Result{}, fmt.Errorf("derive key: %w", err)
	}
	defer crypto.Wipe(key)

	switch pre.version {
	case versionV1:
		return unpackV1(ctx, r, key, pre.nonce, dest, opts)
	case versionV2:
		return unpackV2(ctx, r, key, pre.nonce, dest, opts)
	default:
		return Result{}, fmt.Errorf("%w: %d", ErrUnsupported, pre.version)
	}
}

func unpackV1(ctx context.Context, r io.Reader, key, nonce []byte, dest string, opts UnpackOptions) (Result, error) {
	// Version 1 seals the whole compressed tar in one allocation. Refuse
	// inputs larger than the caller's limit before reading them.
	limited := io.LimitReader(r, opts.MaxBytes+1)
	ciphertext, err := io.ReadAll(limited)
	if err != nil {
		return Result{}, fmt.Errorf("read v1 ciphertext: %w", err)
	}
	if int64(len(ciphertext)) > opts.MaxBytes {
		crypto.Wipe(ciphertext)
		return Result{}, fmt.Errorf("%w: ciphertext exceeds limit", ErrSizeLimit)
	}
	plain, err := crypto.Decrypt(key, nonce, ciphertext, nil)
	crypto.Wipe(ciphertext)
	if err != nil {
		return Result{}, fmt.Errorf("decrypt: %w", err)
	}
	defer crypto.Wipe(plain)

	dec, err := zstd.NewReader(bytes.NewReader(plain),
		zstd.WithDecoderConcurrency(opts.Workers),
		zstd.WithDecoderMaxMemory(windowSize),
	)
	if err != nil {
		return Result{}, fmt.Errorf("create zstd decoder: %w", err)
	}
	defer dec.Close()
	res, err := extractTar(ctx, dec, dest, opts.MaxBytes)
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

func unpackV2(ctx context.Context, r io.Reader, key, prefix []byte, dest string, opts UnpackOptions) (Result, error) {
	cr, err := crypto.NewChunkReader(r, key, prefix, versionV2, opts.MaxBytes)
	if err != nil {
		return Result{}, fmt.Errorf("create decryptor: %w", err)
	}
	dec, err := zstd.NewReader(cr,
		zstd.WithDecoderConcurrency(opts.Workers),
		zstd.WithDecoderMaxMemory(windowSize),
	)
	if err != nil {
		return Result{}, fmt.Errorf("create zstd decoder: %w", err)
	}
	defer dec.Close()
	return extractTar(ctx, dec, dest, opts.MaxBytes)
}

func ensureOutputAvailable(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: output is a symlink", ErrUnsafePath)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: output exists and is not a directory", ErrOutputExists)
	}
	empty, err := dirEmpty(path)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("%w: %s", ErrOutputExists, path)
	}
	return nil
}

func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open output: %w", err)
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read output: %w", err)
	}
	return false, nil
}

func publishDir(tmpDir, dest string) error {
	info, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Rename(tmpDir, dest); err != nil {
			return fmt.Errorf("move unpacked tree: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: output changed during unpack", ErrUnsafePath)
	}
	empty, err := dirEmpty(dest)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("%w: %s", ErrOutputExists, dest)
	}
	if err := os.Remove(dest); err != nil {
		return fmt.Errorf("remove empty output: %w", err)
	}
	if err := os.Rename(tmpDir, dest); err != nil {
		return fmt.Errorf("move unpacked tree: %w", err)
	}
	return nil
}
