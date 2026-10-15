package shield

import "github.com/alphaidea/shield/argon2id"

// Argon2idOptions configures password hashing; zero fields use defaults.
type Argon2idOptions = argon2id.Options

const (
	// DefaultArgon2idMemory is the memory cost in KiB.
	DefaultArgon2idMemory = argon2id.DefaultMemory
	// DefaultArgon2idIterations is the number of passes.
	DefaultArgon2idIterations = argon2id.DefaultIterations
	// DefaultArgon2idParallelism is the number of lanes.
	DefaultArgon2idParallelism = argon2id.DefaultParallelism
	// DefaultArgon2idSaltLength is the salt size in bytes.
	DefaultArgon2idSaltLength = argon2id.DefaultSaltLength
	// DefaultArgon2idHashLength is the hash size in bytes.
	DefaultArgon2idHashLength = argon2id.DefaultHashLength
)

// Argon2idHash hashes a password using peppered Argon2id and a random salt.
// The pepper must be non-empty and kept separate from stored hashes.
func Argon2idHash(pepper, password string) (string, error) {
	return argon2id.Hash(pepper, password)
}

// Argon2idHashWithOptions hashes a password with configurable Argon2id costs
// and sizes. Zero fields use defaults; invalid options return an error.
func Argon2idHashWithOptions(pepper, password string, options Argon2idOptions) (string, error) {
	return argon2id.HashWithOptions(pepper, password, options)
}

// Argon2idVerify checks a password against a peppered Argon2id hash.
// A mismatch returns false, nil; an empty pepper or malformed hash returns an error.
func Argon2idVerify(pepper, password, encoded string) (bool, error) {
	return argon2id.Verify(pepper, password, encoded)
}
