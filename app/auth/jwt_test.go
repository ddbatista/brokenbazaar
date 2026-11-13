package auth

import (
	"encoding/json"
	"strings"
	"testing"
)

// SR-M1-5 (m1-tenancy.md, delivered by M3 T3): "a claim that must not be
// trusted should not be present." A hardened token is minted with OrgID
// and Role empty, and an empty claim must be ABSENT from the payload, not
// present as "" -- a key that exists invites a future handler to read it.
func TestEmptyOrgAndRoleClaimsAreAbsentFromThePayload(t *testing.T) {
	tok, err := Encode(Claims{Sub: "u1", Iss: Issuer, Iat: 1, Exp: 2}, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	payload := payloadKeys(t, tok)
	for _, k := range []string{"org_id", "role"} {
		if _, ok := payload[k]; ok {
			t.Errorf("payload carries %q although it was empty: %v", k, payload)
		}
	}
	for _, k := range []string{"sub", "iss", "iat", "exp"} {
		if _, ok := payload[k]; !ok {
			t.Errorf("payload lost %q: %v", k, payload)
		}
	}
}

// Vulnerable tokens keep both claims: finding 02's bug is trusting org_id,
// and the vulnerable path reads role from the token (plan M3 T3 D2).
func TestSetOrgAndRoleClaimsArePresent(t *testing.T) {
	tok, err := Encode(Claims{Sub: "u1", OrgID: "o1", Role: "viewer", Iss: Issuer, Iat: 1, Exp: 2}, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	payload := payloadKeys(t, tok)
	if payload["org_id"] != "o1" || payload["role"] != "viewer" {
		t.Errorf("payload = %v", payload)
	}
}

func payloadKeys(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
