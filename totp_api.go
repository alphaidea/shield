package shield

import (
	"time"

	"github.com/alphaidea/shield/totp"
)

// TOTPOptions configures the algorithm, digits, period and verification skew.
type TOTPOptions = totp.Options

// TOTPAlgorithm selects a supported HMAC hash.
type TOTPAlgorithm = totp.Algorithm

const (
	TOTPSHA1                = totp.SHA1
	TOTPSHA256              = totp.SHA256
	TOTPSHA512              = totp.SHA512
	DefaultTOTPAlgorithm    = totp.DefaultAlgorithm
	DefaultTOTPDigits       = totp.DefaultDigits
	DefaultTOTPPeriod       = totp.DefaultPeriod
	DefaultTOTPSkew         = totp.DefaultSkew
	DefaultTOTPSecretLength = totp.DefaultSecretLength
)

// TOTPGenerateSecret returns a fresh 160-bit Base32 secret for one account.
func TOTPGenerateSecret() (string, error) { return totp.GenerateSecret() }

// TOTPGenerate generates a default six-digit code at the supplied time.
func TOTPGenerate(secret string, at time.Time) (string, error) { return totp.Generate(secret, at) }

// TOTPGenerateWithOptions generates a code with explicit parameters.
func TOTPGenerateWithOptions(secret string, at time.Time, options TOTPOptions) (string, error) {
	return totp.GenerateWithOptions(secret, at, options)
}

// TOTPVerify checks a code with +/- one time step of skew. Callers must limit
// attempts and atomically reject reused codes; this function is stateless.
func TOTPVerify(secret, code string, at time.Time) (bool, error) {
	return totp.Verify(secret, code, at)
}

// TOTPVerifyWithOptions verifies a code; Skew zero accepts only the current step.
// Callers must prevent replay and limit attempts, as with TOTPVerify.
func TOTPVerifyWithOptions(secret, code string, at time.Time, options TOTPOptions) (bool, error) {
	return totp.VerifyWithOptions(secret, code, at, options)
}

// TOTPURI returns a default otpauth provisioning URI containing the secret.
func TOTPURI(secret, issuer, account string) (string, error) {
	return totp.URI(secret, issuer, account)
}

// TOTPURIWithOptions returns a provisioning URI with explicit parameters.
func TOTPURIWithOptions(secret, issuer, account string, options TOTPOptions) (string, error) {
	return totp.URIWithOptions(secret, issuer, account, options)
}
