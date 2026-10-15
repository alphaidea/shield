package rsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	cryptorsa "crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const (
	hybridHeader = "SHRSA\x01"
	hybridPrefix = "hybrid:v1:"
)

// EncryptHybrid encrypts data using a fresh AES-256-GCM key wrapped with
// RSA-OAEP-SHA256. key is a PEM public key of at least 2048 bits.
// It returns one envelope containing the version, wrapped key, nonce, ciphertext,
// and authentication tag. The version and wrapped key are authenticated as AAD.
// All data is processed in memory; this is not a streaming file API.
func EncryptHybrid(key, data []byte) ([]byte, error) {
	public, err := ParsePublicKey(key)
	if err != nil {
		return nil, err
	}
	if err = validateKey(public); err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, secret); err != nil {
		return nil, err
	}
	wrapped, err := cryptorsa.EncryptOAEP(sha256.New(), rand.Reader, public, secret, []byte(hybridHeader))
	if err != nil {
		return nil, err
	}
	gcm, err := hybridCipher(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	header := append([]byte(hybridHeader), wrapped...)
	ciphertext := gcm.Seal(nil, nonce, data, header)
	envelope := append(header, nonce...)
	return append(envelope, ciphertext...), nil
}

// DecryptHybrid decrypts and authenticates an EncryptHybrid envelope using a
// PEM private key of at least 2048 bits. It never returns unauthenticated data
// and does not modify its input. It does not accept direct RSA ciphertext.
func DecryptHybrid(key, data []byte) ([]byte, error) {
	private, err := ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err = validateKey(&private.PublicKey); err != nil {
		return nil, err
	}
	boundary := len(hybridHeader) + private.Size()
	if len(data) < boundary+12+16 || !bytes.HasPrefix(data, []byte(hybridHeader)) {
		return nil, errors.New("invalid hybrid ciphertext")
	}
	secret, err := cryptorsa.DecryptOAEP(sha256.New(), rand.Reader, private, data[len(hybridHeader):boundary], []byte(hybridHeader))
	if err != nil {
		return nil, err
	}
	if len(secret) != 32 {
		return nil, errors.New("invalid hybrid key length")
	}
	gcm, err := hybridCipher(secret)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data[boundary:boundary+gcm.NonceSize()], data[boundary+gcm.NonceSize():], data[:boundary])
}

// EncryptHybridString encrypts a string into one "hybrid:v1:"-prefixed Base64
// envelope. key is a PEM public key; AES key management is automatic.
func EncryptHybridString(key, data string) (string, error) {
	envelope, err := EncryptHybrid([]byte(key), []byte(data))
	if err != nil {
		return "", err
	}
	return hybridPrefix + base64.StdEncoding.EncodeToString(envelope), nil
}

// DecryptHybridString decrypts an EncryptHybridString envelope using a PEM
// private key. It does not automatically fall back to direct RSA decryption.
func DecryptHybridString(key, data string) (string, error) {
	if !strings.HasPrefix(data, hybridPrefix) {
		return "", errors.New("unsupported hybrid ciphertext version")
	}
	envelope, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(data, hybridPrefix))
	if err != nil {
		return "", err
	}
	plaintext, err := DecryptHybrid([]byte(key), envelope)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func hybridCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
