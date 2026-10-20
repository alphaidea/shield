package shield

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// RandomBytes returns length cryptographically secure random bytes.
// The length must be positive. As with crypto/rand.Read, an entropy source
// failure terminates the process; the returned error only reports invalid length.
func RandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("shield: random byte length must be positive")
	}
	data := make([]byte, length)
	rand.Read(data)
	return data, nil
}

// RandomToken returns length cryptographically secure random bytes encoded as
// unpadded URL-safe Base64. The length specifies bytes before encoding and must
// be positive. Entropy source failure follows RandomBytes behaviour.
func RandomToken(length int) (string, error) {
	data, err := RandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
