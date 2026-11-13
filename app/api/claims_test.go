package main

import (
	"testing"
	"time"

	"github.com/ddbatista/brokenbazaar/app/auth"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// Plan M3 T3 D4 / SR-M1-5: the hardened issuer mints identity and validity
// only. org_id and role are resolved server-side on every request (SR-B2-2,
// D1), so the token must not carry them -- a claim the hardened path never
// believes is a claim a future handler could believe by mistake.
func TestHardenedTokensCarryNoOrgOrRole(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := mintClaims("u1", "o1", store.RoleAdmin, true, now)
	if c.OrgID != "" || c.Role != "" {
		t.Errorf("hardened claims carry org_id=%q role=%q", c.OrgID, c.Role)
	}
	if c.Sub != "u1" || c.Iss != auth.Issuer || c.Iat != now.Unix() || c.Exp != now.Add(auth.TokenTTL).Unix() {
		t.Errorf("hardened claims = %+v", c)
	}
}

// The vulnerable issuer is M1's, unchanged: org_id is finding 02's
// substrate, and the vulnerable path reads role from the token (plan D2).
func TestVulnerableTokensKeepOrgAndRole(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := mintClaims("u1", "o1", store.RoleViewer, false, now)
	if c.OrgID != "o1" || c.Role != "viewer" || c.Sub != "u1" {
		t.Errorf("vulnerable claims = %+v", c)
	}
}
