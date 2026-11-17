package main

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// Plan M3 T6 D6: the org grants in gateway/policy/data.json are keyed by
// the seed's fixed org ids. The two files are in two languages and one is a
// hardened zone, so nothing else keeps them in step: a renumbered seed org
// would silently lose every grant (fail closed -- every agent call in that
// org denied org_grant_absent), and a grant for an id the seed never
// creates is a grant for nobody. Both drifts fail here.
func TestSeedOrgsMatchPolicyGrants(t *testing.T) {
	raw, err := os.ReadFile("../../../gateway/policy/data.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		OrgGrants map[string][]string `json:"org_grants"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	var seeded, granted []string
	for _, o := range seedData() {
		seeded = append(seeded, o.id)
	}
	for id := range data.OrgGrants {
		granted = append(granted, id)
	}
	sort.Strings(seeded)
	sort.Strings(granted)
	if len(seeded) != len(granted) {
		t.Fatalf("seeded orgs %v, org_grants keys %v: every seeded org needs an entry, and nothing else may have one", seeded, granted)
	}
	for i := range seeded {
		if seeded[i] != granted[i] {
			t.Fatalf("seeded orgs %v, org_grants keys %v", seeded, granted)
		}
	}
}
