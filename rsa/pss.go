package rsa

import (
	"crypto"
	"crypto/rand"
	cryptorsa "crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

// Sign signs the original data using RSA-PSS with SHA-256 and a 32-byte salt.
// key is a PEM private key of at least 2048 bits. Do not pre-hash data.
func Sign(key, data []byte) ([]byte, error) {
	private, err := ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err = validateKey(&private.PublicKey); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return cryptorsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:], &cryptorsa.PSSOptions{SaltLength: cryptorsa.PSSSaltLengthEqualsHash})
}

// Verify verifies the original data and an RSA-PSS-SHA256 signature.
// It accepts both 32-byte salts and legacy automatically sized salts.
// key is a PEM public key of at least 2048 bits. Success returns nil.
func Verify(key, data, signature []byte) error {
	public, err := ParsePublicKey(key)
	if err != nil {
		return err
	}
	if err = validateKey(public); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	return cryptorsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, nil)
}

// SignString signs a string with a PEM private key and returns standard Base64.
func SignString(key, data string) (string, error) {
	signature, err := Sign([]byte(key), []byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyString verifies a string and its standard Base64 signature using a PEM
// public key. Success returns nil; malformed or invalid signatures return errors.
func VerifyString(key, data, signature string) error {
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	return Verify([]byte(key), []byte(data), decoded)
}
