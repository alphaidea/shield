package shield

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

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
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return "", errors.New("failed to decode private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS1 private key: %v", err)
	}

	hasher := hashFunc.New()
	_, err = hasher.Write(msg)
	if err != nil {
		return "", fmt.Errorf("failed to hash message: %v", err)
	}

	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hashFunc, hashed)
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

// RSADecrypt
//
//	@Description: rsa decrypt
//	@param privateKeyBytes
//	@param data
//	@return []byte
//	@return error
func RSADecrypt(privateKeyBytes, data []byte) ([]byte, error) {
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to decode private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
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
