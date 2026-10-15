// Package argon2id hashes and verifies passwords using Argon2id with an
// HMAC-SHA256 pepper prehash.
package argon2id

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// DefaultMemory is the default memory cost in KiB (19 MiB).
	DefaultMemory = 19456
	// DefaultIterations is the default number of passes.
	DefaultIterations = 2
	// DefaultParallelism is the default number of lanes.
	DefaultParallelism = 1
	// DefaultSaltLength is the default salt size in bytes.
	DefaultSaltLength = 16
	// DefaultHashLength is the default hash size in bytes.
	DefaultHashLength = 32

	maximumMemory        = 256 * 1024
	maximumIterations    = 10
	maximumParallelism   = 16
	maximumLength        = 64
	maximumEncodedLength = 256
)

// Options controls Argon2id costs and output sizes. Zero fields use defaults.
// Valid ranges are Memory: 8*Parallelism..262144 KiB, Iterations: 1..10,
// Parallelism: 1..16, SaltLength: 16..64 bytes, HashLength: 16..64 bytes.
// These bounds limit resource usage; they do not guarantee adequate strength.
// Reducing costs below the defaults can weaken password protection.
type Options struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	HashLength  uint32
}

// Hash returns a PHC-encoded Argon2id hash with a fresh random salt.
// A non-empty pepper must be supplied from secure application configuration.
// Keep the pepper separate from stored hashes; losing it prevents verification.
// Password policy, including whether empty passwords are allowed, belongs to callers.
func Hash(pepper, password string) (string, error) {
	return HashWithOptions(pepper, password, Options{})
}

// HashWithOptions hashes a password with explicit costs and sizes.
// Zero fields use the corresponding default constants. The HMAC-SHA256 pepper
// prehash is identical to Hash, and Verify reads the parameters from the result.
func HashWithOptions(pepper, password string, options Options) (string, error) {
	if pepper == "" {
		return "", errors.New("password pepper is empty")
	}
	options = options.defaults()
	if err := options.validate(); err != nil {
		return "", err
	}
	salt := make([]byte, options.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := derive(password, pepper, salt, options)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		options.Memory, options.Iterations, options.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

// Verify checks a password against a hash produced by Hash using the same pepper.
// A wrong password or non-empty wrong pepper returns false, nil. An empty pepper
// or malformed hash returns an error. Parameters are read from the hash and must
// meet the same bounds as Options. Current generation defaults do not affect
// verification of older hashes. Callers must still bound concurrent requests.
func Verify(pepper, password, encoded string) (bool, error) {
	if pepper == "" {
		return false, errors.New("password pepper is empty")
	}
	if len(encoded) > maximumEncodedLength {
		return false, errors.New("invalid password hash format")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false, errors.New("invalid password hash format")
	}
	options, err := parse(parts[3])
	if err != nil {
		return false, err
	}
	salt, err := decode(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid password hash salt: %w", err)
	}
	stored, err := decode(parts[5])
	if err != nil {
		return false, fmt.Errorf("invalid password hash value: %w", err)
	}
	options.SaltLength = uint32(len(salt))
	options.HashLength = uint32(len(stored))
	if err = options.validate(); err != nil {
		return false, err
	}
	actual := derive(password, pepper, salt, options)
	return subtle.ConstantTimeCompare(actual, stored) == 1, nil
}

func decode(encoded string) ([]byte, error) {
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 16 || len(decoded) > maximumLength || base64.RawStdEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("invalid length or non-canonical base64")
	}
	return decoded, nil
}

func derive(password, pepper string, salt []byte, options Options) []byte {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(password))
	return argon2.IDKey(mac.Sum(nil), salt, options.Iterations, options.Memory, options.Parallelism, options.HashLength)
}

func (options Options) defaults() Options {
	if options.Memory == 0 {
		options.Memory = DefaultMemory
	}
	if options.Iterations == 0 {
		options.Iterations = DefaultIterations
	}
	if options.Parallelism == 0 {
		options.Parallelism = DefaultParallelism
	}
	if options.SaltLength == 0 {
		options.SaltLength = DefaultSaltLength
	}
	if options.HashLength == 0 {
		options.HashLength = DefaultHashLength
	}
	return options
}

func (options Options) validate() error {
	if options.Parallelism < 1 || options.Parallelism > maximumParallelism ||
		options.Memory < 8*uint32(options.Parallelism) || options.Memory > maximumMemory ||
		options.Iterations < 1 || options.Iterations > maximumIterations ||
		options.SaltLength < 16 || options.SaltLength > maximumLength ||
		options.HashLength < 16 || options.HashLength > maximumLength {
		return errors.New("password hash parameters out of range")
	}
	return nil
}

func parse(encoded string) (Options, error) {
	parts := strings.Split(encoded, ",")
	if len(parts) != 3 {
		return Options{}, errors.New("invalid password hash parameters")
	}
	var values [3]uint64
	for index, name := range []string{"m=", "t=", "p="} {
		value, err := strconv.ParseUint(strings.TrimPrefix(parts[index], name), 10, 32)
		if err != nil || parts[index] != name+strconv.FormatUint(value, 10) {
			return Options{}, errors.New("invalid password hash parameters")
		}
		values[index] = value
	}
	if values[2] > maximumParallelism {
		return Options{}, errors.New("password hash parallelism out of range")
	}
	options := Options{Memory: uint32(values[0]), Iterations: uint32(values[1]), Parallelism: uint8(values[2]), SaltLength: DefaultSaltLength, HashLength: DefaultHashLength}
	return options, options.validate()
}
