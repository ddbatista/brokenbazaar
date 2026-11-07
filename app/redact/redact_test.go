package redact

import (
	"bytes"
	"os"
	"testing"
)

func TestCredentialNamedFieldsAreRedacted(t *testing.T) {
	in := map[string]string{
		"session_token": "Bearer sk-live-9f3a",
		"api_key":       "AKIAIOSFODNN7EXAMPLE",
		"client_secret": "supersecret",
		"admin_password": "hunter2",
		"password":      "hunter3",
	}
	out := Fields(in)
	for _, k := range []string{"session_token", "api_key", "client_secret", "admin_password", "password"} {
		if out[k] != Redacted {
			t.Fatalf("field %q: want %q, got %q", k, Redacted, out[k])
		}
	}
	// The input is never mutated: redaction produces a copy, so the raw
	// argument map the executor holds is not also the map that leaks if
	// someone logs the wrong one.
	if in["api_key"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatal("Fields mutated its input")
	}
}

func TestFieldsDetectionNeedsSurvive(t *testing.T) {
	// Nothing T9's detector reads matches a credential suffix. If one of
	// these ever comes back redacted, D5.2's detection-visibility
	// requirement has been broken by a schema edit, not by code.
	in := map[string]string{
		"url":   "http://attacker.example/collect?data=x",
		"id":    "4db02253-bccf-4cd0-a513-ae84ea18ead4",
		"host":  "metadata.google.internal",
		"ip":    "169.254.169.254",
		"title": "Acme Corp - Q3 revenue breakdown",
	}
	out := Fields(in)
	for k, v := range in {
		if out[k] != v {
			t.Fatalf("field %q should survive redaction: got %q", k, out[k])
		}
	}
}

func TestNilMapStaysNil(t *testing.T) {
	if Fields(nil) != nil {
		t.Fatal("nil args should stay nil, not become an empty map")
	}
}

// TestResidualIsPinned is the second half of MCP01's regression test
// (D5.4): coverage above, and here the DECLARED leak asserted as known.
// A token inside a URL query VALUE must survive redaction, because
// redaction is by field name, never by value shape. A future change that
// starts mangling URL values must FAIL this test and force a conscious
// re-declaration of the residual in gateway/policy/redact.json -- and it
// would also blind T9's detector, which reads urls from the audit store.
func TestResidualIsPinned(t *testing.T) {
	in := map[string]string{
		"url": "http://collector.example/collect?token=sk-live-9f3a&data=tenant-bytes",
	}
	out := Fields(in)
	if out["url"] != in["url"] {
		t.Fatalf("URL was altered by redaction: %q -- the residual is declared, not fixable in silence", out["url"])
	}
}

// TestEmbeddedCopyMatchesPolicyFile is the drift guard that makes the
// copy in this directory honest. The authoritative list is the hardened
// zone file; this embedded copy must be byte-identical to it or the two
// languages are redacting against different schemas -- which is silent
// until a real credential lands in a committed file (D5.4's stated
// failure mode for the rejected duplicated-lists option).
func TestEmbeddedCopyMatchesPolicyFile(t *testing.T) {
	src, err := os.ReadFile("../../gateway/policy/redact.json")
	if err != nil {
		t.Fatalf("cannot read the authoritative schema: %v", err)
	}
	if !bytes.Equal(src, embeddedSchema) {
		t.Fatal("drift: app/redact/redact.json and gateway/policy/redact.json differ -- regenerate the embedded copy (cp gateway/policy/redact.json app/redact/redact.json)")
	}
}
