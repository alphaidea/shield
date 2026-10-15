package shield

import "github.com/alphaidea/shield/aes"

// CBCEncryptString encrypts data using the legacy CBC hexadecimal format.
//
// Deprecated: use AESEncryptString.
func CBCEncryptString(key, data string) (string, error) {
	return aes.CBCEncryptString(key, data)
}

// CBCDecryptString decrypts legacy CBC hexadecimal ciphertext.
//
// Deprecated: use AESDecryptString for new GCM ciphertext. Retain this
// function only for legacy CBC data, which is not authenticated.
func CBCDecryptString(key, data string) (string, error) {
	return aes.CBCDecryptString(key, data)
}

// CBCEncrypt encrypts data using the legacy IV-prefixed CBC format.
//
// Deprecated: use AESEncrypt.
func CBCEncrypt(key, data []byte) ([]byte, error) {
	return aes.CBCEncrypt(key, data)
}

// CBCDecrypt decrypts legacy IV-prefixed CBC ciphertext.
//
// Deprecated: use AESDecrypt for new GCM ciphertext. Retain this function
// only for legacy CBC data, which is not authenticated.
func CBCDecrypt(key, data []byte) ([]byte, error) {
	return aes.CBCDecrypt(key, data)
}
