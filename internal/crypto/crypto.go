// Package crypto encrypts archive payloads with AES-256-GCM.
// Keys are derived with Argon2id. Nonces come from crypto/rand and are
// never reused with the same key.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
)

const (
	// SaltSize is the Argon2 salt length stored in the archive header.
	SaltSize = 16
	// NonceSize is the AES-GCM nonce length.
	NonceSize = 12
	// NoncePrefixSize is the random prefix of a streaming nonce.
	// The remaining 4 bytes are a per-archive chunk counter.
	NoncePrefixSize = 8
	// KeySize is the AES-256 key length.
	KeySize = 32
	// TagSize is the AES-GCM authentication tag length.
	TagSize = 16

	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
)

// DefaultKDF is the production Argon2id parameter set.
// Unpack accepts only parameters inside the bounds enforced by KDFParams.Validate,
// so a crafted archive cannot force a more expensive derivation than this.
var DefaultKDF = KDFParams{
	Time:    argonTime,
	Memory:  argonMemory,
	Threads: argonThreads,
}

// KDFParams selects Argon2id cost. The zero value is not valid; use DefaultKDF.
type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

var (
	// ErrInvalidKey is returned when a key is not KeySize bytes.
	ErrInvalidKey = errors.New("crypto: invalid key size")
	// ErrInvalidNonce is returned when a nonce is not NonceSize bytes.
	ErrInvalidNonce = errors.New("crypto: invalid nonce size")
	// ErrAuthentication is returned when GCM authentication fails.
	// The underlying cipher error is not wrapped, so callers cannot
	// distinguish corruption from a wrong password.
	ErrAuthentication = errors.New("crypto: authentication failed")
	// ErrInvalidKDF is returned when Argon2id parameters are outside the accepted range.
	ErrInvalidKDF = errors.New("crypto: invalid kdf parameters")
	// ErrTruncated is returned when a streaming ciphertext ends before the final chunk.
	ErrTruncated = errors.New("crypto: truncated ciphertext")
	// ErrFormat is returned when a streaming frame is malformed.
	ErrFormat = errors.New("crypto: invalid ciphertext")
	// ErrLimit is returned when a streaming plaintext exceeds the caller limit.
	ErrLimit = errors.New("crypto: plaintext limit exceeded")
)

// Validate rejects parameter sets that are weaker than the minimum we are
// willing to write, or more expensive than DefaultKDF (denial of service).
func (p KDFParams) Validate() error {
	const minMemory = 8 * 1024
	switch {
	case p.Time < 1 || p.Time > DefaultKDF.Time:
		return fmt.Errorf("%w: time %d", ErrInvalidKDF, p.Time)
	case p.Memory < minMemory || p.Memory > DefaultKDF.Memory:
		return fmt.Errorf("%w: memory %d", ErrInvalidKDF, p.Memory)
	case p.Threads < 1 || p.Threads > DefaultKDF.Threads:
		return fmt.Errorf("%w: threads %d", ErrInvalidKDF, p.Threads)
	default:
		return nil
	}
}

// OrDefault returns DefaultKDF when p is the zero value.
func (p KDFParams) OrDefault() (KDFParams, error) {
	if p == (KDFParams{}) {
		return DefaultKDF, nil
	}
	if err := p.Validate(); err != nil {
		return KDFParams{}, err
	}
	return p, nil
}

// DeriveKey derives a KeySize key from password and salt.
// Caller must Wipe the returned key when finished.
func DeriveKey(password, salt []byte, p KDFParams) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("%w: salt length %d", ErrInvalidKDF, len(salt))
	}
	params, err := p.OrDefault()
	if err != nil {
		return nil, err
	}
	sum := argon2ID(password, salt, params)
	return sum, nil
}

// Encrypt seals plaintext with AES-256-GCM.
// nonce must be unique for key. additional data is authenticated but not encrypted.
func Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Decrypt opens ciphertext sealed by Encrypt.
// On authentication failure the error is ErrAuthentication.
func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plain, nil
}

// GenerateSalt returns a random SaltSize salt.
func GenerateSalt() ([]byte, error) {
	return random(SaltSize)
}

// GenerateNonce returns a random NonceSize nonce for single-shot encryption.
func GenerateNonce() ([]byte, error) {
	return random(NonceSize)
}

// GenerateNoncePrefix returns the random prefix used by streaming encryption.
func GenerateNoncePrefix() ([]byte, error) {
	return random(NoncePrefixSize)
}

// Wipe overwrites b. The compiler is prevented from deleting the loop
// via runtime.KeepAlive. Wiping does not clear copies the runtime may
// already have made.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return aead, nil
}

func random(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}
