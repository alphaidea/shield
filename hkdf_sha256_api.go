package shield

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// HKDFSHA256 derives length bytes from secret using HKDF-SHA256 (RFC 5869).
// The length must be between 1 and 8160 bytes. Salt may be nil and info may be
// empty; callers define info to distinguish key purposes. Secret is input key
// material, not a password; use Argon2id for password hashing.
func HKDFSHA256(secret, salt []byte, info string, length int) ([]byte, error) {
	if length <= 0 || length > 255*sha256.Size {
		return nil, fmt.Errorf("shield: HKDF-SHA256 length must be between 1 and %d bytes", 255*sha256.Size)
	}
	return hkdf.Key(sha256.New, secret, salt, info, length)
}
