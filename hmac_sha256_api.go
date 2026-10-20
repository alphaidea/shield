package shield

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// HMACSHA256 returns the HMAC-SHA256 of data using key as lowercase hexadecimal.
// Both key and data may be empty.
func HMACSHA256(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACSHA256Verify verifies a hexadecimal HMAC-SHA256 of data using key.
// A mismatch returns false, nil; malformed hexadecimal or a MAC that is not
// 32 bytes returns an error. Uppercase and lowercase hexadecimal are accepted.
// Both key and data may be empty. MAC comparison uses hmac.Equal.
func HMACSHA256Verify(key, data []byte, encoded string) (bool, error) {
	if len(encoded) != sha256.Size*2 {
		return false, fmt.Errorf("shield: HMAC-SHA256 must contain %d hexadecimal characters", sha256.Size*2)
	}
	provided, err := hex.DecodeString(encoded)
	if err != nil {
		return false, fmt.Errorf("shield: invalid HMAC-SHA256 hexadecimal: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hmac.Equal(provided, mac.Sum(nil)), nil
}

// HMACSHA256Stream reads reader to EOF and returns its HMAC-SHA256 using key as
// lowercase hexadecimal. If reading fails, it returns an empty string and the
// read error. It does not close or rewind reader. The key may be empty.
func HMACSHA256Stream(key []byte, reader io.Reader) (string, error) {
	mac := hmac.New(sha256.New, key)
	if _, err := io.Copy(mac, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}
