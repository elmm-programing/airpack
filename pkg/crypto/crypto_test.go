package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{7}, KeySize)
	nonce := bytes.Repeat([]byte{3}, NonceSize)
	plain := []byte("project source")
	aad := []byte("aad")

	sealed, err := Encrypt(key, nonce, plain, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := Decrypt(key, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext = %q, want %q", got, plain)
	}
}

func TestDecryptRejectsTamperAndWrongKey(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{9}, KeySize)
	nonce := bytes.Repeat([]byte{1}, NonceSize)
	sealed, err := Encrypt(key, nonce, []byte("data"), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := Decrypt(key, nonce, sealed, nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v, want authentication failure", err)
	}

	other := bytes.Repeat([]byte{8}, KeySize)
	sealed, err = Encrypt(key, nonce, []byte("data"), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(other, nonce, sealed, nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key error = %v, want authentication failure", err)
	}
}

func TestEncryptRejectsBadSizes(t *testing.T) {
	t.Parallel()
	if _, err := Encrypt([]byte("short"), bytes.Repeat([]byte{1}, NonceSize), []byte("x"), nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("key error = %v", err)
	}
	if _, err := Encrypt(bytes.Repeat([]byte{1}, KeySize), []byte("short"), []byte("x"), nil); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("nonce error = %v", err)
	}
}

func TestKDFParams(t *testing.T) {
	t.Parallel()
	if _, err := DefaultKDF.OrDefault(); err != nil {
		t.Fatal(err)
	}
	if _, err := (KDFParams{}).OrDefault(); err != nil {
		t.Fatal(err)
	}
	if err := (KDFParams{Time: 1, Memory: 1024, Threads: 1}).Validate(); !errors.Is(err, ErrInvalidKDF) {
		t.Fatalf("weak memory error = %v", err)
	}
	if err := (KDFParams{Time: 99, Memory: DefaultKDF.Memory, Threads: 1}).Validate(); !errors.Is(err, ErrInvalidKDF) {
		t.Fatalf("expensive time error = %v", err)
	}
	salt := bytes.Repeat([]byte{2}, SaltSize)
	key, err := DeriveKey([]byte("pw"), salt, KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeySize {
		t.Fatalf("key length = %d", len(key))
	}
	if _, err := DeriveKey([]byte("pw"), []byte("short"), DefaultKDF); !errors.Is(err, ErrInvalidKDF) {
		t.Fatalf("salt error = %v", err)
	}
}

func TestChunkStreamRoundTripAndIntegrity(t *testing.T) {
	t.Parallel()
	key := make([]byte, KeySize)
	prefix := make([]byte, NoncePrefixSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(prefix); err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("abc"), ChunkSize/2)

	var buf bytes.Buffer
	w, err := NewChunkWriter(&buf, key, prefix, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(nil), buf.Bytes()...)

	got, err := readAllChunks(bytes.NewReader(wire), key, prefix, int64(len(plain))+10)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip length = %d, want %d", len(got), len(plain))
	}

	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)/2] ^= 0xff
	if _, err := readAllChunks(bytes.NewReader(tampered), key, prefix, int64(len(plain))+10); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}

	truncated := wire[:len(wire)/2]
	if _, err := readAllChunks(bytes.NewReader(truncated), key, prefix, int64(len(plain))+10); !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrAuthentication) {
		t.Fatalf("truncate error = %v", err)
	}

	if _, err := readAllChunks(bytes.NewReader(wire), key, prefix, 16); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit error = %v", err)
	}

	// Swap the first two frames. Each frame is header + ciphertext.
	swapped, err := swapFirstChunks(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAllChunks(bytes.NewReader(swapped), key, prefix, int64(len(plain))+10); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("reorder error = %v", err)
	}
}

func TestChunkStreamRejectsTrailingBytes(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{4}, KeySize)
	prefix := bytes.Repeat([]byte{5}, NoncePrefixSize)
	var buf bytes.Buffer
	w, err := NewChunkWriter(&buf, key, prefix, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	buf.WriteByte(0x01)
	if _, err := readAllChunks(&buf, key, prefix, 100); !errors.Is(err, ErrFormat) {
		t.Fatalf("trailing error = %v", err)
	}
}

func readAllChunks(r io.Reader, key, prefix []byte, max int64) ([]byte, error) {
	cr, err := NewChunkReader(r, key, prefix, 2, max)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(cr)
}

func swapFirstChunks(wire []byte) ([]byte, error) {
	first, rest, err := splitChunk(wire)
	if err != nil {
		return nil, err
	}
	second, tail, err := splitChunk(rest)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), second...)
	out = append(out, first...)
	out = append(out, tail...)
	return out, nil
}

func splitChunk(wire []byte) (chunk, rest []byte, err error) {
	if len(wire) < 5 {
		return nil, nil, ErrTruncated
	}
	clen := int(wire[1])<<24 | int(wire[2])<<16 | int(wire[3])<<8 | int(wire[4])
	total := 5 + clen
	if len(wire) < total {
		return nil, nil, ErrTruncated
	}
	return wire[:total], wire[total:], nil
}
