package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// HashPassword and VerifyPassword back the seed data now and, from M1 T4,
// the hardened half of POST /auth/token (SR-B1-2: a verifiable credential,
// not just an email). Hand-rolled and stdlib-only on purpose, same reasoning
// as the JWT verifier (D3): no KDF (bcrypt/argon2/scrypt) ships in the Go
// standard library, and adding one is a dependency proposal this module
// does not need. This is good enough to seed a lab honestly -- salted,
// constant-time compared -- and is explicitly not a production credential
// store (R-M1-4, declared non-coverage).
//
// Stored format: "<salt-hex>:<sha256-hex>".
func HashPassword(password string) (string, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", fmt.Errorf("store: generating salt: %w", err)
	}
	sum := sha256.Sum256(append(salt[:], password...))
	return hex.EncodeToString(salt[:]) + ":" + hex.EncodeToString(sum[:]), nil
}

// VerifyPassword reports whether password matches stored. It never returns
// an error -- a malformed stored hash is not distinguishable, to the caller,
// from a wrong password; both must fail the same way.
func VerifyPassword(password, stored string) bool {
	saltHex, sumHex, ok := strings.Cut(stored, ":")
	if !ok {
		return false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(sumHex)
	if err != nil {
		return false
	}
	got := sha256.Sum256(append(salt, password...))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
