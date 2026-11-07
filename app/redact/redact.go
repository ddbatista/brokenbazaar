// Package redact is the Go half of M2's write-time redaction (MCP01, D5.4).
// One schema governs three writers in two languages:
//
//	gateway/policy/redact.json   the authoritative list (hardened zone --
//	                             what counts as a secret is policy)
//	app/redact/redact.json       a byte-copy, embedded at build time
//	gateway/redact.py            the Python half, runtime-read
//
// The copy exists because go:embed cannot reach outside the package
// directory, and the byte-drift test in redact_test.go is what keeps the
// copy honest: the two files cannot differ without a red build. Redaction
// is by field NAME, never by value shape (M2-N2: a pattern is a denylist,
// and a redaction test against a pattern only proves the pattern catches
// what it was written to catch).
//
// The declared residual lives in the schema file itself (_residual): URL
// query parameters and novel field names are NOT covered, and the
// residual-pinning tests in both languages assert a token inside a URL
// SURVIVES -- so a future "fix" that mangles URLs fails a test instead of
// silently blinding detection (T9 reads urls from the audit store, D5.2).
//
// M2's Go callers pass flat map[string]string arguments, so this is a
// flat walk; the Python half walks nested structures for the same schema,
// because the gateway's payload args arrive as arbitrary JSON.
package redact

import (
	_ "embed"
	"encoding/json"
)

//go:embed redact.json
var embeddedSchema []byte

// Redacted is the single replacement token. Credential VALUES become this
// string everywhere (D1b), in every store, in both languages.
const Redacted = "[REDACTED]"

type schema struct {
	Headers      []string `json:"headers"`
	FieldsExact  []string `json:"fields_exact"`
	FieldsSuffix []string `json:"fields_suffix"`
}

var loaded = loadSchema()

func loadSchema() *schema {
	var s schema
	if err := json.Unmarshal(embeddedSchema, &s); err != nil {
		// A malformed embedded schema is a build-artifact problem, not a
		// runtime condition: fail loudly at init rather than fail open --
		// the same ordering SR-B5-6 gives the audit writer.
		panic("redact: embedded schema is not valid JSON: " + err.Error())
	}
	return &s
}

// SchemaBytes exposes the embedded copy for the drift test.
func SchemaBytes() []byte { return embeddedSchema }

// match reports whether a field name is credential-shaped: an exact hit
// or a known suffix. Over-matching is the intended bias -- a record that
// loses a harmless field costs nothing, and nothing detection needs
// (url, host, ip, tool) matches a credential suffix.
func match(key string, s *schema) bool {
	for _, exact := range s.FieldsExact {
		if key == exact {
			return true
		}
	}
	for _, suffix := range s.FieldsSuffix {
		if len(key) > len(suffix) && key[len(key)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

// Fields returns a redacted copy of an argument map. The input is never
// mutated; a nil map stays nil so callers can distinguish "no args" from
// "empty args" if they ever need to.
func Fields(args map[string]string) map[string]string {
	if args == nil {
		return nil
	}
	out := make(map[string]string, len(args))
	for k, v := range args {
		if match(k, loaded) {
			out[k] = Redacted
		} else {
			out[k] = v
		}
	}
	return out
}
