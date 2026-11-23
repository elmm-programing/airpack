//go:build unix

package packer

import (
	"os"
	"syscall"
)

// openNoFollow opens path for reading and fails if the last element is a symlink.
// Packing must not follow links: a link can point at files outside the project.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
