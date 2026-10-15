package shield

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

// MD5 returns the MD5 checksum of str as lowercase hexadecimal.
func MD5(str string) string {
	return MD5Small(str)
}

// MD5Small returns the MD5 checksum of str as lowercase hexadecimal.
func MD5Small(str string) string {
	sum := md5.Sum([]byte(str))
	return hex.EncodeToString(sum[:])
}

// MD5stream reads r to EOF and returns its MD5 checksum as lowercase hexadecimal.
// If reading fails, it returns an empty string and the read error.
func MD5stream(r io.Reader) (string, error) {
	h := md5.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
