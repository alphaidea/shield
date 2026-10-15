// Package totp implements RFC 6238 time-based one-time passwords.
// Verification is stateless; callers must prevent replay and limit attempts.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm selects the HMAC hash used by TOTP.
type Algorithm string

const (
	SHA1                Algorithm = "SHA1"
	SHA256              Algorithm = "SHA256"
	SHA512              Algorithm = "SHA512"
	DefaultAlgorithm              = SHA1
	DefaultDigits                 = 6
	DefaultPeriod                 = 30 // Seconds.
	DefaultSkew                   = 1  // Accepted steps before and after the current step.
	DefaultSecretLength           = 20 // Random bytes, before Base32 encoding.
)

// Options configures TOTP. Zero Algorithm, Digits and Period use defaults.
// Digits must be 6 or 8; Period is in seconds (1..86400); Skew is 0..10.
// Skew applies only to verification, with zero accepting exactly the current step.
// Both the authenticator and server must use the same Algorithm, Digits and Period.
type Options struct {
	Algorithm Algorithm
	Digits    int
	Period    uint32
	Skew      uint8
}

// GenerateSecret returns a fresh 160-bit secret as uppercase, unpadded Base32.
// Generate one per account and store it encrypted; do not log or hash it.
func GenerateSecret() (string, error) {
	secret := make([]byte, DefaultSecretLength)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// Generate returns the default six-digit code at the given time.
func Generate(secret string, at time.Time) (string, error) {
	return GenerateWithOptions(secret, at, Options{})
}

// GenerateWithOptions returns the code using the specified parameters.
// The epoch is Unix zero. Times before the epoch are rejected.
func GenerateWithOptions(secret string, at time.Time, options Options) (string, error) {
	options, err := options.normalise()
	if err != nil {
		return "", err
	}
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	if at.Unix() < 0 {
		return "", errors.New("TOTP time precedes Unix epoch")
	}
	return generate(key, uint64(at.Unix())/uint64(options.Period), options), nil
}

// Verify checks a code at the given time using defaults and +/- one step of skew.
// A malformed code or mismatch returns false, nil; invalid secrets, options or
// times return an error. It does not consume a code or enforce one-time use.
func Verify(secret, code string, at time.Time) (bool, error) {
	return VerifyWithOptions(secret, code, at, Options{Skew: DefaultSkew})
}

// VerifyWithOptions verifies a code within the configured skew window.
// Skew zero accepts only the current step. Preserve leading zeroes in code.
// Callers must atomically reject codes already used while they remain valid.
func VerifyWithOptions(secret, code string, at time.Time, options Options) (bool, error) {
	options, err := options.normalise()
	if err != nil {
		return false, err
	}
	key, err := decode(secret)
	if err != nil {
		return false, err
	}
	if at.Unix() < 0 {
		return false, errors.New("TOTP time precedes Unix epoch")
	}
	if len(code) != options.Digits {
		return false, nil
	}
	for index := range code {
		if code[index] < '0' || code[index] > '9' {
			return false, nil
		}
	}
	counter := uint64(at.Unix()) / uint64(options.Period)
	matches := 0
	for offset := -int(options.Skew); offset <= int(options.Skew); offset++ {
		var candidate uint64
		if offset < 0 {
			if counter < uint64(-offset) {
				continue
			}
			candidate = counter - uint64(-offset)
		} else {
			candidate = counter + uint64(offset)
		}
		matches |= subtle.ConstantTimeCompare([]byte(code), []byte(generate(key, candidate, options)))
	}
	return matches == 1, nil
}

// URI returns an otpauth://totp URI using the default parameters.
// The URI contains the secret; render it as a QR code locally, never through a
// third-party QR service. Issuer and account must be non-empty and contain no colon.
func URI(secret, issuer, account string) (string, error) {
	return URIWithOptions(secret, issuer, account, Options{})
}

// URIWithOptions returns a provisioning URI with explicit algorithm parameters.
// Skew is a server-only policy and is not included in the URI.
func URIWithOptions(secret, issuer, account string, options Options) (string, error) {
	options, err := options.normalise()
	if err != nil {
		return "", err
	}
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(account) == "" || strings.ContainsAny(issuer+account, ":") {
		return "", errors.New("TOTP issuer and account must be non-empty and contain no colon")
	}
	parameters := url.Values{
		"secret":    {base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)},
		"issuer":    {issuer},
		"algorithm": {string(options.Algorithm)},
		"digits":    {strconv.Itoa(options.Digits)},
		"period":    {strconv.FormatUint(uint64(options.Period), 10)},
	}
	address := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + account,
		RawPath: "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account), RawQuery: parameters.Encode()}
	return address.String(), nil
}

func (options Options) normalise() (Options, error) {
	if options.Algorithm == "" {
		options.Algorithm = DefaultAlgorithm
	}
	if options.Digits == 0 {
		options.Digits = DefaultDigits
	}
	if options.Period == 0 {
		options.Period = DefaultPeriod
	}
	if options.Algorithm != SHA1 && options.Algorithm != SHA256 && options.Algorithm != SHA512 ||
		options.Digits != 6 && options.Digits != 8 || options.Period > 86400 || options.Skew > 10 {
		return Options{}, errors.New("invalid TOTP options")
	}
	return options, nil
}

func decode(secret string) ([]byte, error) {
	if len(secret) > 205 {
		return nil, errors.New("TOTP secret exceeds 128 bytes")
	}
	encoded := strings.ToUpper(secret)
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil || len(key) < 16 || len(key) > 128 ||
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key) != encoded {
		return nil, errors.New("TOTP secret must be canonical unpadded Base32 encoding of 16..128 bytes")
	}
	return key, nil
}

func generate(key []byte, counter uint64, options Options) string {
	var constructor func() hash.Hash
	switch options.Algorithm {
	case SHA256:
		constructor = sha256.New
	case SHA512:
		constructor = sha512.New
	default:
		constructor = sha1.New
	}
	mac := hmac.New(constructor, key)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if options.Digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", options.Digits, value%modulus)
}
