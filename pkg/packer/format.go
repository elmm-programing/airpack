package packer

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/edwinlmm/aipack/pkg/crypto"
)

const (
	magic       = "AIPK"
	versionV1   = 1
	versionV2   = 2
	v2HeaderLen = 38
	// windowSize caps the zstd window so a hostile frame cannot force a
	// multi-gigabyte allocation. The encoder is pinned to the same size.
	windowSize = 8 << 20
)

func writeV2Header(w io.Writer, params crypto.KDFParams, salt, prefix []byte) error {
	if len(salt) != crypto.SaltSize || len(prefix) != crypto.NoncePrefixSize {
		return fmt.Errorf("%w: header material", ErrBadArchive)
	}
	var buf [v2HeaderLen]byte
	copy(buf[:4], magic)
	buf[4] = versionV2
	binary.BigEndian.PutUint32(buf[5:9], params.Time)
	binary.BigEndian.PutUint32(buf[9:13], params.Memory)
	buf[13] = params.Threads
	copy(buf[14:30], salt)
	copy(buf[30:38], prefix)
	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write archive header: %w", err)
	}
	return nil
}

type preamble struct {
	version byte
	params  crypto.KDFParams
	salt    []byte
	nonce   []byte // v1: full nonce; v2: nonce prefix
}

func readPreamble(r io.Reader) (preamble, error) {
	var lead [5]byte
	if _, err := io.ReadFull(r, lead[:]); err != nil {
		return preamble{}, fmt.Errorf("read archive header: %w", err)
	}
	if string(lead[:4]) != magic {
		return preamble{}, fmt.Errorf("%w: bad magic", ErrBadArchive)
	}
	switch lead[4] {
	case versionV1:
		return readV1Rest(r)
	case versionV2:
		return readV2Rest(r)
	default:
		return preamble{}, fmt.Errorf("%w: %d", ErrUnsupported, lead[4])
	}
}

func readV1Rest(r io.Reader) (preamble, error) {
	var rest [crypto.SaltSize + crypto.NonceSize]byte
	if _, err := io.ReadFull(r, rest[:]); err != nil {
		return preamble{}, fmt.Errorf("read v1 header: %w", err)
	}
	return preamble{
		version: versionV1,
		params:  crypto.DefaultKDF,
		salt:    append([]byte(nil), rest[:crypto.SaltSize]...),
		nonce:   append([]byte(nil), rest[crypto.SaltSize:]...),
	}, nil
}

func readV2Rest(r io.Reader) (preamble, error) {
	var rest [v2HeaderLen - 5]byte
	if _, err := io.ReadFull(r, rest[:]); err != nil {
		return preamble{}, fmt.Errorf("read v2 header: %w", err)
	}
	params := crypto.KDFParams{
		Time:    binary.BigEndian.Uint32(rest[0:4]),
		Memory:  binary.BigEndian.Uint32(rest[4:8]),
		Threads: rest[8],
	}
	if err := params.Validate(); err != nil {
		return preamble{}, err
	}
	return preamble{
		version: versionV2,
		params:  params,
		salt:    append([]byte(nil), rest[9:25]...),
		nonce:   append([]byte(nil), rest[25:33]...),
	}, nil
}
