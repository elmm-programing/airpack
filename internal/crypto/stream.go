package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// ChunkSize is the plaintext size of every non-final streaming frame.
// The final frame is shorter and is authenticated as final, so truncation
// cannot be hidden by dropping the tail.
const ChunkSize = 1 << 20

const (
	chunkHeaderLen = 5
	flagFinal      = 1
)

// ChunkWriter encrypts a byte stream as a sequence of AES-GCM frames.
// Each frame uses nonce = prefix || uint32be(counter). The counter starts
// at zero and is never reused for a given prefix. Associated data binds
// the archive version, the counter, and whether the frame is final.
//
// Write calls must not overlap. zstd's encoder serializes writes to its
// output, which is the only production caller.
type ChunkWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	prefix  []byte
	version byte
	buf     []byte
	n       int
	counter uint32
	closed  bool
}

// NewChunkWriter returns a writer that frames plaintext to w.
// prefix must be NoncePrefixSize bytes from GenerateNoncePrefix.
// version is bound into every frame's associated data.
func NewChunkWriter(w io.Writer, key, prefix []byte, version byte) (*ChunkWriter, error) {
	if len(prefix) != NoncePrefixSize {
		return nil, ErrInvalidNonce
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &ChunkWriter{
		w:       w,
		aead:    aead,
		prefix:  append([]byte(nil), prefix...),
		version: version,
		buf:     make([]byte, ChunkSize),
	}, nil
}

// Write buffers p and emits full frames. It returns a short write only
// when framing or the underlying writer fails.
func (c *ChunkWriter) Write(p []byte) (int, error) {
	if c.closed {
		return 0, ErrFormat
	}
	written := 0
	for len(p) > 0 {
		if c.n == ChunkSize {
			if err := c.flush(false); err != nil {
				return written, err
			}
		}
		k := copy(c.buf[c.n:], p)
		c.n += k
		p = p[k:]
		written += k
	}
	return written, nil
}

// Close writes the final frame, which may be empty, and refuses later writes.
func (c *ChunkWriter) Close() error {
	if c.closed {
		return nil
	}
	return c.flush(true)
}

func (c *ChunkWriter) flush(final bool) error {
	if !final && c.n == 0 {
		return nil
	}
	if !final && c.n != ChunkSize {
		return ErrFormat
	}
	nonce, err := chunkNonce(c.prefix, c.counter)
	if err != nil {
		return err
	}
	sealed := c.aead.Seal(nil, nonce, c.buf[:c.n], chunkAAD(c.version, c.counter, final))
	Wipe(c.buf[:c.n])
	plainLen := c.n
	c.n = 0

	var hdr [chunkHeaderLen]byte
	if final {
		hdr[0] = flagFinal
	}
	if len(sealed) > math.MaxUint32 {
		return ErrFormat
	}
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(sealed)))
	if _, err := c.w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write chunk header: %w", err)
	}
	if _, err := c.w.Write(sealed); err != nil {
		return fmt.Errorf("write chunk: %w", err)
	}
	if final {
		c.closed = true
		return nil
	}
	if c.counter == math.MaxUint32 {
		return ErrFormat
	}
	c.counter++
	if plainLen != ChunkSize {
		return ErrFormat
	}
	return nil
}

// ChunkReader decrypts frames produced by ChunkWriter.
// maxPlain is the maximum number of plaintext bytes that will be returned.
// A larger stream fails with ErrFormat instead of allocating without bound.
type ChunkReader struct {
	r        io.Reader
	aead     cipher.AEAD
	prefix   []byte
	version  byte
	pending  []byte
	counter  uint32
	done     bool
	read     int64
	maxPlain int64
}

// NewChunkReader returns a reader over a framed ciphertext stream.
func NewChunkReader(r io.Reader, key, prefix []byte, version byte, maxPlain int64) (*ChunkReader, error) {
	if len(prefix) != NoncePrefixSize {
		return nil, ErrInvalidNonce
	}
	if maxPlain <= 0 {
		return nil, ErrFormat
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &ChunkReader{
		r:        r,
		aead:     aead,
		prefix:   append([]byte(nil), prefix...),
		version:  version,
		maxPlain: maxPlain,
	}, nil
}

// Read returns decrypted plaintext. io.EOF is returned only after the
// authenticated final frame has been consumed. A stream that ends earlier
// returns ErrTruncated.
func (c *ChunkReader) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.done {
			return 0, io.EOF
		}
		if err := c.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.pending)
	Wipe(c.pending[:n])
	c.pending = c.pending[n:]
	return n, nil
}

func (c *ChunkReader) next() error {
	var hdr [chunkHeaderLen]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrTruncated
		}
		return fmt.Errorf("read chunk header: %w", err)
	}
	final := hdr[0] == flagFinal
	if hdr[0] != 0 && hdr[0] != flagFinal {
		return ErrFormat
	}
	clen := binary.BigEndian.Uint32(hdr[1:])
	if clen < TagSize || clen > ChunkSize+TagSize {
		return ErrFormat
	}
	sealed := make([]byte, clen)
	if _, err := io.ReadFull(c.r, sealed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrTruncated
		}
		return fmt.Errorf("read chunk: %w", err)
	}
	nonce, err := chunkNonce(c.prefix, c.counter)
	if err != nil {
		return err
	}
	plain, err := c.aead.Open(nil, nonce, sealed, chunkAAD(c.version, c.counter, final))
	if err != nil {
		return ErrAuthentication
	}
	if !final && len(plain) != ChunkSize {
		Wipe(plain)
		return ErrFormat
	}
	if final && len(plain) > ChunkSize {
		Wipe(plain)
		return ErrFormat
	}
	if int64(len(plain)) > c.maxPlain-c.read {
		Wipe(plain)
		return ErrLimit
	}
	c.read += int64(len(plain))
	c.pending = plain
	if c.counter == math.MaxUint32 && !final {
		return ErrFormat
	}
	if !final {
		c.counter++
	}
	if final {
		c.done = true
		extra := make([]byte, 1)
		n, err := c.r.Read(extra)
		if n > 0 {
			return ErrFormat
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read trailer: %w", err)
		}
	}
	return nil
}

func chunkNonce(prefix []byte, counter uint32) ([]byte, error) {
	if len(prefix) != NoncePrefixSize {
		return nil, ErrInvalidNonce
	}
	nonce := make([]byte, NonceSize)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[NoncePrefixSize:], counter)
	return nonce, nil
}

func chunkAAD(version byte, counter uint32, final bool) []byte {
	aad := make([]byte, 10)
	copy(aad, "AIPK")
	aad[4] = version
	binary.BigEndian.PutUint32(aad[5:], counter)
	if final {
		aad[9] = 1
	}
	return aad
}
