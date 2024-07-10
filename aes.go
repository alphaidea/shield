package shield

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// CBCEncryptString
//
//	@Description: AES CBC Encryption
//	@param key
//	@param data
//	@return string
//	@return error
func CBCEncryptString(key, data string) (string, error) {
	encryptBytes, err := CBCEncrypt([]byte(key), []byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptBytes), nil
}

// CBCDecryptString
//
//	@Description: AES CBC Decryption
//	@param key
//	@param data
//	@return string
//	@return error
func CBCDecryptString(key, data string) (string, error) {
	bytesData, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	decryptBytes, err := CBCDecrypt([]byte(key), bytesData)
	if err != nil {
		return "", err
	}
	return string(decryptBytes), nil
}

// CBCEncrypt
//
//	@Description: AES CBC Encryption
//	@param key
//	@param data
//	@return []byte
//	@return error
func CBCEncrypt(key, data []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key length must be 16, 24, or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	// generate a random IV
	var iv = make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	encryptBytes := pkcs7Padding(data, blockSize)

	var result = make([]byte, len(iv)+len(encryptBytes))

	copy(result, iv)

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(result[blockSize:], encryptBytes)

	return result, nil
}

// CBCDecrypt
//
//	@Description: AES CBC Decryption
//	@param key
//	@param data
//	@return []byte
//	@return error
func CBCDecrypt(key, data []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid length of key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	// The IV is the first block of data
	iv := data[:blockSize]
	data = data[blockSize:]

	if len(data)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	// decrypt data
	blockMode.CryptBlocks(data, data)

	return pkcs7UnPadding(data), nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	result := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, result...)
}

func pkcs7UnPadding(data []byte) []byte {
	length := len(data)
	unPadding := int(data[length-1])
	return data[:(length - unPadding)]
}
