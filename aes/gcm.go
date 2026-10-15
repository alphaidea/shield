// Package aes provides AES encryption. Encrypt and EncryptString use
// authenticated AES-GCM by default; CBC functions support legacy ciphertext.
package aes

import (
	cryptoaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const gcmPrefix = "v1:"

// Encrypt encrypts data using AES-GCM with a fresh random nonce.
// The key must contain 16, 24, or 32 raw bytes, not a password or encoded key.
// The result contains the nonce followed by the ciphertext and authentication tag.
// Do not encrypt more than 2^32 messages with the same key across all callers.
func Encrypt(key, data []byte) ([]byte, error) {
	return GCMEncrypt(key, data)
}

// Decrypt decrypts and authenticates data produced by Encrypt or GCMEncrypt.
// It does not modify data and does not accept legacy CBC ciphertext.
func Decrypt(key, data []byte) ([]byte, error) {
	return GCMDecrypt(key, data)
}

// EncryptString encrypts data using AES-GCM and returns "v1:" followed by
// standard Base64 encoding of the nonce, ciphertext, and authentication tag.
// The key must contain 16, 24, or 32 raw bytes; it is not hex-decoded.
// Do not encrypt more than 2^32 messages with the same key across all callers.
func EncryptString(key, data string) (string, error) {
	return GCMEncryptString(key, data)
}

// DecryptString decrypts and authenticates a string produced by EncryptString
// or GCMEncryptString. Legacy CBC ciphertext must use CBCDecryptString.
func DecryptString(key, data string) (string, error) {
	return GCMDecryptString(key, data)
}

// GCMEncrypt is the explicit AES-GCM equivalent of Encrypt.
func GCMEncrypt(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize(), gcm.NonceSize()+len(data)+gcm.Overhead())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// GCMDecrypt is the explicit AES-GCM equivalent of Decrypt.
func GCMDecrypt(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("invalid GCM ciphertext length")
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}

// GCMEncryptString is the explicit AES-GCM equivalent of EncryptString.
func GCMEncryptString(key, data string) (string, error) {
	ciphertext, err := GCMEncrypt([]byte(key), []byte(data))
	if err != nil {
		return "", err
	}
	return gcmPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// GCMDecryptString is the explicit AES-GCM equivalent of DecryptString.
func GCMDecryptString(key, data string) (string, error) {
	if !strings.HasPrefix(data, gcmPrefix) {
		return "", errors.New("unsupported GCM ciphertext version")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(data, gcmPrefix))
	if err != nil {
		return "", err
	}
	plaintext, err := GCMDecrypt([]byte(key), ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := cryptoaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
