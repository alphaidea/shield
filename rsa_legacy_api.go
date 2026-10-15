package shield

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	shieldrsa "github.com/alphaidea/shield/rsa"
)

// parsePrivateKey
//
//	@Description: parse private key from PEM bytes
//	@param privateKeyBytes
//	@return *rsa.PrivateKey
//	@return error
func parsePrivateKey(privateKeyBytes []byte) (*rsa.PrivateKey, error) {
	return shieldrsa.ParsePrivateKey(privateKeyBytes)
}

// GetRSAKey
//
// Deprecated: use RSAGenerateKey.
// This compatibility API retains PKCS#1 output and caller-selected key sizes.
//
//	@Description: get rsa key
//	@param bits
//	@return string
//	@return string
//	@return error
func GetRSAKey(bits int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	privateStream := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := generatePEMBlock("RSA PRIVATE KEY", privateStream)

	publicKey := &privateKey.PublicKey
	publicStream, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyPEM := generatePEMBlock("PUBLIC KEY", publicStream)

	return privateKeyPEM, publicKeyPEM, nil
}

// GetRSASignature
//
// Deprecated: use RSASign or RSASignString for SHA-256 signatures.
// This compatibility API retains caller-selected hashes and automatic PSS salt.
//
//	@Description: get rsa signature
//	@param privateKeyBytes
//	@param msg
//	@param hashFunc
//	@return string
//	@return error
func GetRSASignature(privateKeyBytes, msg []byte, hashFunc crypto.Hash) (string, error) {
	if !hashFunc.Available() {
		return "", errors.New("unavailable signature hash")
	}
	privateKey, err := parsePrivateKey(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	hasher := hashFunc.New()
	hasher.Write(msg)
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, hashFunc, hashed, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// GetDecryptMsg
//
// Deprecated: use RSADecryptString.
//
//	@Description: get decrypt message
//	@param privateKeyString
//	@param data
//	@return []byte
//	@return error
func GetDecryptMsg(privateKeyString, data string) ([]byte, error) {
	privateKeyBytes := []byte(privateKeyString)
	dataBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return RSADecrypt(privateKeyBytes, dataBytes)
}

// RSAEncrypt
//
// Deprecated: use RSAEncryptString for a minimum key size of 2048 bits,
// or RSAEncryptHybrid.
//
//	@Description: rsa encrypt with OAEP and SHA-256
//	@param publicKeyBytes
//	@param data
//	@return []byte
//	@return error
func RSAEncrypt(publicKeyBytes, data []byte) ([]byte, error) {
	publicKey, err := shieldrsa.ParsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

// GetEncryptMsg
//
// Deprecated: use RSAEncryptString.
//
//	@Description: get encrypt message
//	@param publicKeyString
//	@param data
//	@return string
//	@return error
func GetEncryptMsg(publicKeyString string, data []byte) (string, error) {
	publicKeyBytes := []byte(publicKeyString)
	encrypted, err := RSAEncrypt(publicKeyBytes, data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// RSADecrypt
//
// Deprecated: use RSADecryptString for a minimum key size of 2048 bits,
// or RSADecryptHybrid.
//
//	@Description: rsa decrypt with Optimal Asymmetric Encryption Padding
//	@param privateKeyBytes
//	@param data
//	@return []byte
//	@return error
func RSADecrypt(privateKeyBytes, data []byte) ([]byte, error) {
	privateKey, err := parsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
}

// generatePEMBlock
//
//	@Description: generate pem block
//	@param typeStr
//	@param bytes
//	@return string
func generatePEMBlock(typeStr string, bytes []byte) string {
	block := pem.Block{
		Type:  typeStr,
		Bytes: bytes,
	}

	return string(pem.EncodeToMemory(&block))
}
