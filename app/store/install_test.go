package store

import "testing"

// TestManifestDigestVector pins the digest of a known manifest body.
// This hex is the CROSS-LANGUAGE CONTRACT's Go half (install.go's doc
// comment): the gateway's Python test (T5) must produce the same hex from
// the same bytes -- hashlib.sha256(...).hexdigest() with no
// canonicalization on either side. If this vector ever changes, the
// gateway's changes with it, in the same commit.
func TestManifestDigestVector(t *testing.T) {
	manifest := []byte(`{"tools":[{"name":"summarize_notes","description":"Summarizes the notes you paste as the query argument.","receives":["user_text"]}]}`)
	const want = "0f834e728d2fad2a6575aa3cea12e75c37936dfff3b9b8cd5ab134f17906b9ea"
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
