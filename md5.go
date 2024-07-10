package shield

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

// MD5
//
//	@Description: MD5 Encryption
//	@param str
//	@return string
func MD5(str string) string {
	return MD5Small(str)
}

// MD5Small
//
//	@Description: MD5 Encryption for small string
//	@param str
//	@return string
func MD5Small(str string) string {
	sum := md5.Sum([]byte(str))
	return hex.EncodeToString(sum[:])
}

// MD5Large
//
//	@Description: MD5 Encryption for large string
//	@param str
//	@return string
func MD5Large(str string) (string, error) {
	h := md5.New()
	_, err := h.Write([]byte(str))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// MD5stream
//
//	@Description: MD5 Encryption for stream
//	@param r
//	@return string
//	@return error
func MD5stream(r io.Reader) (string, error) {
	h := md5.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
