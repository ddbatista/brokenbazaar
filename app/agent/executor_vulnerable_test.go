//go:build vulnerable

package agent

import (
	"context"
	"strings"
	"testing"
)

// Plan M3 T4 D1 / T5 D4: the write tools pass the same name-only check as M2's
// two tools (B5 3.2), and nothing else does.
func TestNaiveAllowlistNamesTheWriteTools(t *testing.T) {
	want := []string{"read_document", "http_fetch", "update_document", "delete_document", "set_member_role"}
	for _, tool := range want {
		if !naiveAllowedTools[tool] {
			t.Errorf("naiveAllowedTools is missing %q", tool)
		}
	}
	if len(naiveAllowedTools) != len(want) {
		t.Errorf("naiveAllowedTools has %d tools, want exactly %v", len(naiveAllowedTools), want)
	}
}

// Argument checks run before the store is touched: the executor here
// has a nil pool, so any path that reached the database would panic.
// A missing body is refused rather than read as "", which would wipe the
// document on a malformed call; an explicitly empty body is a real
// update, as it is on the direct route.
func TestWriteToolsCheckArgumentsBeforeTheStore(t *testing.T) {
	e := &NaiveExecutor{cfg: ExecutorConfig{OrgID: "00000000-0000-0000-0000-000000000000"}}
	cases := []struct {
		tool string
		args map[string]string
		want string
	}{
		{"delete_document", map[string]string{}, "requires an id"},
		{"update_document", map[string]string{"body": "x"}, "requires an id"},
		{"update_document", map[string]string{"id": targetID}, "requires a body"},
		{"set_member_role", map[string]string{"role": "admin"}, "requires a user"},
		{"set_member_role", map[string]string{"user": targetID, "role": "owner"}, "unknown role"},
		{"set_member_role", map[string]string{"user": targetID}, "unknown role"},
	}
	call := CallContext{Session: SessionInfo{ID: otherID, OrgID: e.cfg.OrgID, ActingFor: otherID}}
	for _, c := range cases {
		_, err := e.Execute(context.Background(), Action{Tool: c.tool, Args: c.args}, call)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: want an error containing %q, got %v", c.tool, c.args, c.want, err)
		}
	}
}

// Plan M3 T5 D4: the role change is attributed to the session it came through --
// the acting user and the session id, from the platform's CallContext,
// never from the model. A call with no session to attribute it to is
// refused before the store: an unattributed role change is exactly the
// silent change SR-B8-7 forbids.
func TestRoleChangeNeedsASessionToAttributeItTo(t *testing.T) {
	e := &NaiveExecutor{cfg: ExecutorConfig{OrgID: "00000000-0000-0000-0000-000000000000"}}
	args := map[string]string{"user": targetID, "role": "admin"}
	for _, call := range []CallContext{
		{},
		{Session: SessionInfo{ID: otherID}},
		{Session: SessionInfo{ActingFor: otherID}},
	} {
		_, err := e.Execute(context.Background(), Action{Tool: "set_member_role", Args: args}, call)
		if err == nil || !strings.Contains(err.Error(), "attribute") {
			t.Errorf("session %+v: want a refusal naming attribution, got %v", call.Session, err)
		}
	}
}
