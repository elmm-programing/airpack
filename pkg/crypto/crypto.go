package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize   = 16
	NonceSize  = 12 // AES-GCM standard
	KeySize    = 32 // AES-256
	ArgonTime  = 3
	ArgonMemory = 64 * 1024 // 64 MB
	ArgonThreads = 4
	ArgonKeyLen = KeySize
)

// DeriveKey derives a 32-byte key from password and salt using Argon2id.
func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
}

// Encrypt encrypts plaintext with AES-256-GCM. Returns ciphertext with nonce prepended? No, nonce separate.
// Caller provides nonce or we generate.
func Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("invalid nonce size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with AES-256-GCM.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("invalid nonce size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: authentication error or corrupted data")
	}
	return plaintext, nil
}

// GenerateSalt generates a cryptographically secure salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateNonce generates a cryptographically secure nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
