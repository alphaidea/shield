// Package rsa provides RSA-OAEP encryption and RSA-PSS signatures with SHA-256.
// Direct encryption is for short messages; explicit hybrid encryption uses
// AES-256-GCM for content and RSA-OAEP for its randomly generated key.
package rsa

import (
	"bytes"
	"crypto/rand"
	cryptorsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// GenerateKey returns a PKCS#8 private key and PKIX public key, both PEM-encoded,
// in that order. The default size is 2048 bits. Supply one optional size to use
// a larger key. Sizes below 2048 bits are rejected.
func GenerateKey(bits ...int) (string, string, error) {
	size := 2048
	if len(bits) > 1 {
		return "", "", errors.New("expected at most one RSA key size")
	}
	if len(bits) == 1 {
		size = bits[0]
	}
	if size < 2048 {
		return "", "", errors.New("RSA key must be at least 2048 bits")
	}
	key, err := cryptorsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return "", "", err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})), nil
}

// ParsePrivateKey accepts PEM-encoded PKCS#1 and PKCS#8 RSA private keys.
// It also accepts historical shield PKCS#1 keys labelled "PRIVATE KEY".
// Parsing imposes no minimum size; new encryption and signing APIs require
// at least 2048 bits, while callers of legacy APIs retain their existing policy.
func ParsePrivateKey(data []byte) (*cryptorsa.PrivateKey, error) {
	block, err := decodeKey(data)
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			private, ok := key.(*cryptorsa.PrivateKey)
			if !ok {
				return nil, errors.New("private key is not RSA")
			}
			return private, nil
		}
		// Older shield releases emitted PKCS#1 DER with this PKCS#8 label.
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
}

// ParsePublicKey accepts PEM-encoded PKIX and PKCS#1 RSA public keys.
// Parsing imposes no minimum size; new encryption and verification APIs require
// at least 2048 bits.
func ParsePublicKey(data []byte) (*cryptorsa.PublicKey, error) {
	block, err := decodeKey(data)
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		public, ok := key.(*cryptorsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}
		return public, nil
	default:
		return nil, fmt.Errorf("unsupported public key PEM type %q", block.Type)
	}
}

func decodeKey(data []byte) (*pem.Block, error) {
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, errors.New("invalid key PEM")
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid key PEM")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after PEM block")
	}
	return block, nil
}

func validateKey(key *cryptorsa.PublicKey) error {
	if key.N == nil || key.N.BitLen() < 2048 {
		return errors.New("RSA key must be at least 2048 bits")
	}
	return nil
}
