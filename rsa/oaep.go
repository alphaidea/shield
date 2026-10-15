package rsa

import (
	"crypto/rand"
	cryptorsa "crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

// Encrypt encrypts short data using RSA-OAEP with SHA-256 and an empty label.
// key is a PEM public key of at least 2048 bits. The maximum data length is
// key.Size()-66 bytes (190 bytes for a 2048-bit key). Longer data returns
// crypto/rsa.ErrMessageTooLong; use EncryptHybrid for larger messages.
func Encrypt(key, data []byte) ([]byte, error) {
	public, err := ParsePublicKey(key)
	if err != nil {
		return nil, err
	}
	if err = validateKey(public); err != nil {
		return nil, err
	}
	return cryptorsa.EncryptOAEP(sha256.New(), rand.Reader, public, data, nil)
}

// Decrypt decrypts RSA-OAEP-SHA256 ciphertext using a PEM private key of at
// least 2048 bits. It does not accept hybrid envelopes or modify data.
func Decrypt(key, data []byte) ([]byte, error) {
	private, err := ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err = validateKey(&private.PublicKey); err != nil {
		return nil, err
	}
	return cryptorsa.DecryptOAEP(sha256.New(), rand.Reader, private, data, nil)
}

// EncryptString encrypts a short string and returns standard Base64 ciphertext.
// key is a PEM public key. The size limit counts UTF-8 bytes, not characters.
func EncryptString(key, data string) (string, error) {
	ciphertext, err := Encrypt([]byte(key), []byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts standard Base64 RSA-OAEP ciphertext with a PEM private key.
func DecryptString(key, data string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	plaintext, err := Decrypt([]byte(key), ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
