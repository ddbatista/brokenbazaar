//go:build vulnerable

package agent

import (
	"context"
	"strings"
	"testing"
)

// M3 T4 D1: the write tools pass the same name-only check as M2's two
// tools (B5 3.2), and set_member_role is not among them yet (T5).
func TestNaiveAllowlistNamesTheWriteTools(t *testing.T) {
	for _, tool := range []string{"read_document", "http_fetch", "update_document", "delete_document"} {
		if !naiveAllowedTools[tool] {
			t.Errorf("naiveAllowedTools is missing %q", tool)
		}
	}
	if naiveAllowedTools["set_member_role"] {
		t.Error("set_member_role arrives in T5, not T4")
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
	}
	for _, c := range cases {
		_, err := e.Execute(context.Background(), Action{Tool: c.tool, Args: c.args}, CallContext{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: want an error containing %q, got %v", c.tool, c.args, c.want, err)
		}
	}
}
