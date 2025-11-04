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
)

// parsePrivateKey
//
//	@Description: parse private key from PEM bytes
//	@param privateKeyBytes
//	@return *rsa.PrivateKey
//	@return error
func parsePrivateKey(privateKeyBytes []byte) (*rsa.PrivateKey, error) {
	privateKeyBlock, rest := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to decode private key")
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after PEM block")
	}
	return x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
}

// GetRSAKey
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
	privateKeyPEM := generatePEMBlock("PRIVATE KEY", privateStream)

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
//	@Description: get rsa signature
//	@param privateKeyBytes
//	@param msg
//	@param hashFunc
//	@return string
//	@return error
func GetRSASignature(privateKeyBytes, msg []byte, hashFunc crypto.Hash) (string, error) {
	privateKey, err := parsePrivateKey(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	hasher := hashFunc.New()
	hasher.Write(msg)
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, hashFunc, hashed, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// GetDecryptMsg
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
//	@Description: rsa encrypt with OAEP and SHA-256
//	@param publicKeyBytes
//	@param data
//	@return []byte
//	@return error
func RSAEncrypt(publicKeyBytes, data []byte) ([]byte, error) {
	publicKeyBlock, rest := pem.Decode(publicKeyBytes)
	if publicKeyBlock == nil {
		return nil, errors.New("failed to decode public key")
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA key")
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, data, nil)
}

// GetEncryptMsg
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
