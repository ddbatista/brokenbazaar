package store

import "testing"

// TestManifestDigestVector pins the digest of a known manifest body.
// This hex is the CROSS-LANGUAGE CONTRACT's Go half (install.go's doc
// comment): the gateway's Python test (T5) must produce the same hex from
// the same bytes -- hashlib.sha256(...).hexdigest() with no
// canonicalization on either side. If this vector ever changes, the
// gateway's changes with it, in the same commit.
//
// The body is the FULL tools/list response, envelope included (package
// mcp owns the shape): what the server returned is what is hashed,
// stored and compared -- nothing is ever extracted or re-serialized.
func TestManifestDigestVector(t *testing.T) {
	manifest := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_notes","description":"Summarizes the notes you paste as the query argument.","receives":["user_text"]}]}}`)
	const want = "802b49df232a5f72a9478b7169fbd159cd9c5c1b32bbc4e28d75b0b4d964e557"
	if got := ManifestDigest(manifest); got != want {
		t.Fatalf("ManifestDigest = %q, want %q (the gateway's Python vector must agree)", got, want)
	}
	// Byte-exactness, not equivalence: the same manifest re-serialized
	// with different whitespace is a DIFFERENT pin (migration 004's
	// opening rule), and the per-call drift check relies on it -- a
	// server that re-serializes between fetches reads as drift, never as
	// verified (M4a-N2's failure direction).
	if ManifestDigest([]byte(`{"tools": [ {"name": "summarize_notes"} ]}`)) ==
		ManifestDigest([]byte(`{"tools":[{"name":"summarize_notes"}]}`)) {
		t.Fatal("re-serialized manifest produced the same digest; pinning is not byte-exact")
	}
}
