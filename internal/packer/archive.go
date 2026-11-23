package packer

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	dirPerm     os.FileMode = 0o750
	filePerm    os.FileMode = 0o640
	execPerm    os.FileMode = 0o750
	maxEntries              = 1_000_000
	copyBufSize             = 256 * 1024
)

// safeArchivePath returns a cleaned slash-separated path that cannot escape
// the extraction root. os.Root enforces this again at open time; the lexical
// check produces a stable error and rejects control characters before any
// filesystem call.
func safeArchivePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty path", ErrUnsafePath)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: control character in path", ErrUnsafePath)
		}
	}
	// Treat Windows separators as separators so "..\\..\\x" cannot hide on Unix.
	name = strings.ReplaceAll(name, "\\", "/")
	cleaned := path.Clean(name)
	if cleaned == "." {
		return ".", nil
	}
	// filepath.IsLocal is lexical. os.Root repeats the check, including symlinks.
	if !filepath.IsLocal(cleaned) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, truncate(name, 120))
	}
	return cleaned, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func extractTar(ctx context.Context, r io.Reader, dest string, maxBytes int64) (Result, error) {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return Result{}, fmt.Errorf("open output root: %w", err)
	}
	defer root.Close()

	tr := tar.NewReader(r)
	var res Result
	var entries int
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		if err != nil {
			return res, fmt.Errorf("read tar entry: %w", err)
		}
		entries++
		if entries > maxEntries {
			return res, fmt.Errorf("%w: too many entries", ErrSizeLimit)
		}
		if err := extractEntry(ctx, root, tr, hdr, &res, maxBytes); err != nil {
			return res, err
		}
	}
}

func extractEntry(ctx context.Context, root *os.Root, tr *tar.Reader, hdr *tar.Header, res *Result, maxBytes int64) error {
	name, err := safeArchivePath(hdr.Name)
	if err != nil {
		return err
	}
	if name == "." {
		if hdr.Typeflag == tar.TypeDir || hdr.FileInfo().IsDir() {
			return nil
		}
		return fmt.Errorf("%w: file named '.'", ErrUnsafePath)
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := mkdirAllRoot(root, name); err != nil {
			return err
		}
		res.Dirs++
		return nil
	case tar.TypeReg, tar.TypeRegA:
		if hdr.Size < 0 {
			return fmt.Errorf("%w: negative size", ErrBadArchive)
		}
		if hdr.Size > maxBytes || res.Bytes > maxBytes-hdr.Size {
			return fmt.Errorf("%w: extracted data exceeds limit", ErrSizeLimit)
		}
		parent := path.Dir(name)
		if parent != "." {
			if err := mkdirAllRoot(root, parent); err != nil {
				return err
			}
		}
		f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_EXCL, archivePerm(hdr.Mode))
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		n, copyErr := copyContext(ctx, f, tr)
		closeErr := f.Close()
		if copyErr != nil {
			return fmt.Errorf("extract %s: %w", name, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", name, closeErr)
		}
		if n != hdr.Size {
			return fmt.Errorf("%w: short entry %s", ErrBadArchive, name)
		}
		res.Files++
		res.Bytes += n
		return nil
	default:
		return fmt.Errorf("%w: refusing entry type %d (%s)", ErrUnsafePath, hdr.Typeflag, truncate(hdr.Name, 120))
	}
}

func archivePerm(mode int64) os.FileMode {
	if mode&0o111 != 0 {
		return execPerm
	}
	return filePerm
}

func mkdirAllRoot(root *os.Root, name string) error {
	name = path.Clean(name)
	if name == "." || name == "" {
		return nil
	}
	parts := strings.Split(name, "/")
	cur := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if cur == "" {
			cur = part
		} else {
			cur = cur + "/" + part
		}
		err := root.Mkdir(cur, dirPerm)
		if err == nil {
			continue
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create directory %s: %w", cur, err)
		}
		info, statErr := root.Lstat(cur)
		if statErr != nil {
			return fmt.Errorf("stat directory %s: %w", cur, statErr)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: %s exists and is not a directory", ErrUnsafePath, cur)
		}
	}
	return nil
}

// copyContext copies until EOF, checking ctx between buffers so a signal
// interrupts a large file without waiting for the whole copy.
func copyContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, copyBufSize)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			nw, werr := dst.Write(buf[:n])
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
			if nw != n {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return written, nil
			}
			return written, rerr
		}
	}
}
