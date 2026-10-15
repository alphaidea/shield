package shield

import "github.com/alphaidea/shield/aes"

// AESEncrypt encrypts data using AES-GCM.
func AESEncrypt(key, data []byte) ([]byte, error) {
	return aes.Encrypt(key, data)
}

// AESDecrypt authenticates and decrypts AES-GCM ciphertext.
func AESDecrypt(key, data []byte) ([]byte, error) {
	return aes.Decrypt(key, data)
}

// AESEncryptString encrypts data using AES-GCM and returns v1-prefixed Base64.
func AESEncryptString(key, data string) (string, error) {
	return aes.EncryptString(key, data)
}

// AESDecryptString authenticates and decrypts v1-prefixed AES-GCM ciphertext.
func AESDecryptString(key, data string) (string, error) {
	return aes.DecryptString(key, data)
}

// GCMEncrypt encrypts data using AES-GCM.
func GCMEncrypt(key, data []byte) ([]byte, error) {
	return aes.GCMEncrypt(key, data)
}

// GCMDecrypt authenticates and decrypts AES-GCM ciphertext.
func GCMDecrypt(key, data []byte) ([]byte, error) {
	return aes.GCMDecrypt(key, data)
}

// GCMEncryptString encrypts data using AES-GCM and returns v1-prefixed Base64.
func GCMEncryptString(key, data string) (string, error) {
	return aes.GCMEncryptString(key, data)
}

// GCMDecryptString authenticates and decrypts v1-prefixed AES-GCM ciphertext.
func GCMDecryptString(key, data string) (string, error) {
	return aes.GCMDecryptString(key, data)
}
