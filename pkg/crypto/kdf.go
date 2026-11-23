package crypto

import "golang.org/x/crypto/argon2"

// argon2ID is isolated so tests can observe parameter forwarding without
// duplicating the Argon2id call site.
func argon2ID(password, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, KeySize)
}
