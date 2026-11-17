//go:build !vulnerable

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Plan M3 T6 D3: the hardened agent tells the gateway WHICH session is
// acting and nothing else about it. The gateway re-derives the org, the
// acting user and the authority from the session row; a field it ignores
// would be one a later edit could start trusting, so it is not sent at all.
func TestGatePayloadNamesTheSessionOnly(t *testing.T) {
	var got map[string]any
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"route":"deny","decision_id":"d_x","text":"gateway denied","summary":""}`))
	}))
	defer gw.Close()

	e := &GatewayExecutor{gatewayURL: gw.URL, client: gw.Client()}
	call := CallContext{Session: SessionInfo{ID: "s-1", OrgID: "org-1", ActingFor: "u-1"}}
	if _, err := e.Execute(context.Background(), Action{Tool: "read_document", Args: map[string]string{"id": "d"}}, call); err != nil {
		t.Fatal(err)
	}
	session, _ := got["session"].(map[string]any)
	if len(session) != 1 || session["id"] != "s-1" {
		t.Fatalf("payload session = %v, want exactly {id: s-1}", got["session"])
	}
}
