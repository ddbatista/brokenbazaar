package store

import (
	"crypto/rand"
	"fmt"
)

// NewID returns a random UUIDv4 string. Hand-rolled rather than imported:
// crypto/rand is already the dependency that matters (it is the actual
// source of randomness), and pulling in a UUID library for sixteen bytes
// of formatting would put a second RNG wrapper in scope for review with no
// benefit -- see AGENTS.md "do not add dependencies."
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the OS entropy source is gone. Nothing
		// downstream of this call can safely continue.
		panic("store: crypto/rand unavailable: " + err.Error())
	}
	// RFC 4122 version 4 / variant 10 bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
