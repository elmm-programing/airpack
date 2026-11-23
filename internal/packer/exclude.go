package packer

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// builtinExcludes drops VCS metadata, dependency trees, and build products
// so the archive stays small enough to hand to an AI tool.
var builtinExcludes = []string{
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

// DefaultExcludes returns a copy of the built-in exclude patterns.
// Callers may mutate the result.
func DefaultExcludes() []string {
	out := make([]string, len(builtinExcludes))
	copy(out, builtinExcludes)
	return out
}

func validateExcludes(patterns []string) error {
	for _, pattern := range patterns {
		if _, err := path.Match(filepath.ToSlash(pattern), "x"); err != nil {
			return fmt.Errorf("invalid exclude pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// excluded reports whether rel matches a pattern, either as a full slash
// path or as any individual path component. Matching components is what
// makes a directory such as nested/node_modules skip its children.
func excluded(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	if matchAny(rel, patterns) || matchAny(path.Base(rel), patterns) {
		return true
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." {
			continue
		}
		if matchAny(part, patterns) {
			return true
		}
	}
	return false
}

func matchAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		ok, err := path.Match(filepath.ToSlash(pattern), name)
		if err != nil {
			continue
		}
		if ok {
			return true
		}
	}
	return false
}
