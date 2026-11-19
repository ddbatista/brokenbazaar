package authz

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// Plan M3 T6 D1: the per-action authority checks, as a pure function of
// the session row, the requester's CURRENT role, the tool and the clock.
// The plan's acceptance line: "unit tests show allow AND deny for every
// leg" -- a leg tested only on the deny side cannot be told apart from a
// leg that denies everything (T0 D3's lesson, one level down).

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// passing is a session on which every leg passes for delete_document.
func passing() store.SessionAuthority {
	return store.SessionAuthority{
		SessionID: "s1", OrgID: "o1", ActingFor: "u1",
		Scope:     []string{"read_document", "delete_document"},
		ExpiresAt: now.Add(time.Hour),
		RoleNow:   store.RoleAdmin,
	}
}

func TestEveryLegPassesOnAPassingSession(t *testing.T) {
	legs := Derive(passing(), "delete_document", now)
	if legs != (Legs{WithinTime: true, InScope: true, RolePermits: true}) {
		t.Fatalf("got %+v, want every leg passing", legs)
	}
	if legs.Failing() != "" {
		t.Fatalf("Failing() = %q on a passing session", legs.Failing())
	}
}

// Each leg, denied alone: the other two still pass, so the test shows the
// deny comes from THIS leg and not from a function that denies everything.
func TestEachLegDeniesAlone(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*store.SessionAuthority)
		want   Legs
		reason string
	}{
		{"expired", func(s *store.SessionAuthority) { s.ExpiresAt = now.Add(-time.Second) },
			Legs{WithinTime: false, InScope: true, RolePermits: true}, "session_expired"},
		{"expiring exactly now is expired", func(s *store.SessionAuthority) { s.ExpiresAt = now },
			Legs{WithinTime: false, InScope: true, RolePermits: true}, "session_expired"},
		{"tool not in scope", func(s *store.SessionAuthority) { s.Scope = []string{"read_document"} },
			Legs{WithinTime: true, InScope: false, RolePermits: true}, "not_in_session_scope"},
		{"empty scope", func(s *store.SessionAuthority) { s.Scope = []string{} },
			Legs{WithinTime: true, InScope: false, RolePermits: true}, "not_in_session_scope"},
		{"role below the action (demoted to viewer)", func(s *store.SessionAuthority) { s.RoleNow = store.RoleViewer },
			Legs{WithinTime: true, InScope: true, RolePermits: false}, "role_does_not_permit"},
		{"membership gone (no role)", func(s *store.SessionAuthority) { s.RoleNow = "" },
			Legs{WithinTime: true, InScope: true, RolePermits: false}, "role_does_not_permit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := passing()
			c.mutate(&s)
			got := Derive(s, "delete_document", now)
			if got != c.want {
				t.Errorf("legs %+v, want %+v", got, c.want)
			}
			if got.Failing() != c.reason {
				t.Errorf("Failing() = %q, want %q", got.Failing(), c.reason)
			}
		})
	}
}

// The role leg is D1's table, at both boundaries the agent can reach
// (m3-delegation.md D2): a member may update and may not delete.
func TestRoleLegUsesThePermissionTable(t *testing.T) {
	s := passing()
	s.RoleNow = store.RoleMember
	s.Scope = []string{"update_document", "delete_document"}
	if !Derive(s, "update_document", now).RolePermits {
		t.Error("a member may update through the agent (05's positive control)")
	}
	if Derive(s, "delete_document", now).RolePermits {
		t.Error("a member may not delete through the agent")
	}
}

// Failing() reports legs in the policy's order (plan M3 T6 D5), so an
// internal route's 403 names the same reason the gate would have.
func TestFailingReportsTheFirstLegInPolicyOrder(t *testing.T) {
	if got := (Legs{}).Failing(); got != "session_expired" {
		t.Errorf("all failing: %q, want session_expired", got)
	}
	if got := (Legs{WithinTime: true}).Failing(); got != "not_in_session_scope" {
		t.Errorf("scope and role failing: %q, want not_in_session_scope", got)
	}
}

// Plan M3 T6 D1: the tool -> action map. http_fetch is Read (any role may
// fetch), the decision the user closed at T6's open. A tool the map does
// not name has no action, so its role leg fails: fail closed.
func TestToolActions(t *testing.T) {
	want := map[string]Action{
		"read_document":   Read,
		"http_fetch":      Read,
		"update_document": Update,
		"delete_document": Delete,
		"set_member_role": SetMemberRole,
	}
	for tool, action := range want {
		got, ok := ActionFor(tool)
		if !ok || got != action {
			t.Errorf("ActionFor(%q) = %q, %v; want %q", tool, got, ok, action)
		}
	}
	if len(toolActions) != len(want) {
		t.Errorf("toolActions has %d tools, the test covers %d", len(toolActions), len(want))
	}
	for _, tool := range []string{"", "drop_table", "READ_DOCUMENT"} {
		if _, ok := ActionFor(tool); ok {
			t.Errorf("ActionFor(%q) should not map", tool)
		}
		s := passing()
		s.Scope = append(s.Scope, tool)
		if Derive(s, tool, now).RolePermits {
			t.Errorf("unknown tool %q passed the role leg", tool)
		}
	}
}

// set_member_role passes the ROLE leg for an admin. That is correct and
// load-bearing: the role leg is the ceiling (05), not delegability (06).
// If this ever failed, 06's hardened denial would come from the wrong
// control, and the gateway policy's non_delegable leg
// (control_plane_not_delegable, M3 T7) would be untested.
func TestAdminPassesTheRoleLegForSetMemberRole(t *testing.T) {
	s := passing()
	s.Scope = []string{"set_member_role"}
	if !Derive(s, "set_member_role", now).RolePermits {
		t.Fatal("an admin's role permits set_member_role; delegability is the policy's control_plane_not_delegable leg")
	}
}

// Legs.Failing() names reasons the gateway policy also names, in the same
// order. The two live in two languages and one is a hardened zone, so
// nothing else holds them together: a renamed Rego reason, or a reorder,
// would make an internal route's refusal disagree with the gate's decision
// for the same call. Both drifts fail here.
func TestFailingMatchesThePolicysLegOrder(t *testing.T) {
	raw, err := os.ReadFile("../../gateway/policy/policy.rego")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "leg_order := [")
	end := strings.Index(src[start:], "]")
	if start < 0 || end < 0 {
		t.Fatal("policy.rego has no leg_order list")
	}
	order := src[start : start+end]
	reasons := []string{(Legs{}).Failing(), (Legs{WithinTime: true}).Failing(), (Legs{WithinTime: true, InScope: true}).Failing()}
	last := -1
	for _, r := range reasons {
		at := strings.Index(order, `"`+r+`"`)
		if at < 0 {
			t.Fatalf("Failing() names %q, which policy.rego's leg_order does not", r)
		}
		if at < last {
			t.Fatalf("policy.rego orders %q before the leg Failing() reports ahead of it", r)
		}
		last = at
	}
}

// Every tool the gateway policy knows has an action in the one permission
// table. A tool listed in data.tools without one would pass the tool leg and
// then fail the role leg for every role, admin included -- a silent outage
// that reads as role_does_not_permit (the false-denial shape T0 D3 is about).
func TestEveryPolicyToolHasAnAction(t *testing.T) {
	raw, err := os.ReadFile("../../gateway/policy/data.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for _, tool := range data.Tools {
		if _, ok := ActionFor(tool); !ok {
			t.Errorf("data.tools lists %q, which has no action in toolActions", tool)
		}
	}
}
