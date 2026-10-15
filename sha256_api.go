package shield

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// SHA256 returns the SHA-256 checksum of data as lowercase hexadecimal.
func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Stream reads reader to EOF and returns its SHA-256 checksum as lowercase
// hexadecimal. If reading fails, it returns an empty string and the read error.
// It does not close or rewind reader.
func SHA256Stream(reader io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
