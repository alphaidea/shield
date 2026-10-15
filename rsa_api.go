package shield

import (
	cryptorsa "crypto/rsa"

	"github.com/alphaidea/shield/rsa"
)

// RSAGenerateKey generates PEM private and public keys, defaulting to 2048 bits.
// It rejects keys smaller than 2048 bits.
func RSAGenerateKey(bits ...int) (string, string, error) {
	return rsa.GenerateKey(bits...)
}

// RSAParsePrivateKey parses a PEM private key without restricting its size.
func RSAParsePrivateKey(data []byte) (*cryptorsa.PrivateKey, error) {
	return rsa.ParsePrivateKey(data)
}

// RSAParsePublicKey parses a PEM public key without restricting its size.
func RSAParsePublicKey(data []byte) (*cryptorsa.PublicKey, error) {
	return rsa.ParsePublicKey(data)
}

// RSAEncryptString encrypts short data using RSA-OAEP-SHA256 and returns Base64.
// It rejects keys smaller than 2048 bits.
func RSAEncryptString(key, data string) (string, error) {
	return rsa.EncryptString(key, data)
}

// RSADecryptString decrypts Base64 RSA-OAEP-SHA256 ciphertext.
// It rejects keys smaller than 2048 bits.
func RSADecryptString(key, data string) (string, error) {
	return rsa.DecryptString(key, data)
}

// RSAEncryptHybrid encrypts data using RSA-OAEP-SHA256 and AES-256-GCM.
func RSAEncryptHybrid(key, data []byte) ([]byte, error) {
	return rsa.EncryptHybrid(key, data)
}

// RSADecryptHybrid authenticates and decrypts a hybrid encryption envelope.
func RSADecryptHybrid(key, data []byte) ([]byte, error) {
	return rsa.DecryptHybrid(key, data)
}

// RSAEncryptHybridString encrypts data and returns a hybrid:v1-prefixed Base64 envelope.
func RSAEncryptHybridString(key, data string) (string, error) {
	return rsa.EncryptHybridString(key, data)
}

// RSADecryptHybridString authenticates and decrypts a hybrid:v1-prefixed envelope.
func RSADecryptHybridString(key, data string) (string, error) {
	return rsa.DecryptHybridString(key, data)
}

// RSASign signs data using RSA-PSS-SHA256 with a 32-byte salt.
func RSASign(key, data []byte) ([]byte, error) {
	return rsa.Sign(key, data)
}

// RSAVerify verifies an RSA-PSS-SHA256 signature.
func RSAVerify(key, data, signature []byte) error {
	return rsa.Verify(key, data, signature)
}

// RSASignString signs data using RSA-PSS-SHA256 and returns Base64.
func RSASignString(key, data string) (string, error) {
	return rsa.SignString(key, data)
}

// RSAVerifyString verifies a Base64 RSA-PSS-SHA256 signature.
func RSAVerifyString(key, data, signature string) error {
	return rsa.VerifyString(key, data, signature)
}
