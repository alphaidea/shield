# shield

A Go library for encryption, password hashing, and authentication with simple APIs.

- AES-GCM and RSA-OAEP encryption, including hybrid encryption for larger data.
- RSA-PSS signing and verification.
- Argon2id password hashing and TOTP authentication.
- SHA-256 checksums and legacy AES-CBC, RSA, and MD5 compatibility.
- HMAC-SHA256 message authentication and verification for byte slices, with stream computation.
- Cryptographically secure random bytes and URL-safe tokens.
- HKDF-SHA256 key derivation.

Import `github.com/alphaidea/shield` for unified APIs, or use individual subpackages.