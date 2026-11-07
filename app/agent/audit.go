package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ddbatista/brokenbazaar/app/redact"
)

// AgentAudit is D4's second writer: the agent loop's own record of the
// calls it makes, in the same schema as the gateway's JSONL, with
// mediated:false because no decision was made -- in vulnerable mode the
// gateway was never asked (SR-B5-9's "the vulnerable mode is not silent").
//
// WHY A SECOND WRITER AT ALL. With the gateway as sole writer, the
// vulnerable mode would have no telemetry, and T9's detect-vs-miss matrix
// would have nothing to measure a miss on. Two files also snapshot
// independently (M1's collection-window lesson), and the CONTRAST between
// them is the measurement: vulnerable runs grow audit/agent.jsonl,
// hardened runs grow audit/gateway.jsonl and agent.jsonl stays empty.
//
// The ID convention is shared with the gateway's records but disjoint:
// agent-minted ids are "a_"-prefixed, gateway-minted ids are "d_"-, and
// only "d_" ids ever reach the tool_calls citation column (the schema
// CHECK enforces the pairing with route != 'unmediated'). An "a_" id is a
// correlation key joining this file's own pre and post lines -- D4's
// "the ID demotes itself from auth token to join key" -- and nothing else.
//
// Ordering, same as the gate's (D4): the pre-record is appended and
// fsynced BEFORE the executor is called, and the id is returned -- becomes
// real, usable, citable -- only after the write is durable. An id that
// existed before its record could cite a record that does not exist.
//
// The schema on the wire matches D5.2 exactly: full inputs (args
// redacted, provenance carried), route "unmediated", reasons null. The
// post line is lean: outcome, summary, duration.
//
// Only vulnerable builds construct one; see NewAgentAudit in the
// build-tagged executor files. The hardened loop holds nil and skips
// every call here -- the gateway's records are the whole audit trail in
// that mode, which is the structural claim D5 makes about mediation.
type AgentAudit struct {
	path string
}

// defaultAgentAuditPath mirrors the gateway's default
// (audit/gateway.jsonl); both overridable by env so Compose can mount one
// volume for both writers (T6).
const defaultAgentAuditPath = "audit/agent.jsonl"

func newAgentAuditID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is a broken host, not a condition to log
		// around: an audit writer that cannot mint ids cannot guarantee
		// its own pre/post correlation.
		panic("agent audit: cannot read random bytes for an id: " + err.Error())
	}
	return "a_" + hex.EncodeToString(b)
}

func auditStamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// openAgentAudit probes the path at construction so an unwritable audit
// destination is a STARTUP failure, not a mid-run surprise (the same
// loud-or-absent rule as every other credential and path in this repo).
func openAgentAudit(path string) (*AgentAudit, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("agent audit: creating %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("agent audit: opening %s: %w", path, err)
	}
	return &AgentAudit{path: path}, f.Close()
}

// write appends one JSONL line and fsyncs it. Per-record open/write/fsync
// is slower than a held handle and is chosen on purpose: durability here
// is a property of the RECORD, and one line per file operation leaves no
// buffering window in which a record could be "written" but not durable.
func (a *AgentAudit) write(rec map[string]any) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("agent audit: encoding record: %w", err)
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("agent audit: opening %s: %w", a.path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("agent audit: appending: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("agent audit: fsync: %w", err)
	}
	return nil
}

// Pre records a call before dispatch. The returned id exists for the
// caller only after this returns nil -- see the ordering note above.
func (a *AgentAudit) Pre(action Action, call CallContext) (string, error) {
	id := newAgentAuditID()
	rec := map[string]any{
		"ts":          auditStamp(),
		"phase":       "pre",
		"decision_id": id,
		"session":     call.Session.ID,
		"acting_for":  call.Session.ActingFor,
		"org":         call.Session.OrgID,
		"tool":        action.Tool,
		"args":        redact.Fields(action.Args),
		"provenance":  map[string]any{"derived_from": call.DerivedFrom},
		"route":       "unmediated",
		"mediated":    false,
		"reasons":     nil,
	}
	if err := a.write(rec); err != nil {
		return "", err
	}
	return id, nil
}

// Post records the call's completion with the pre-record's id.
func (a *AgentAudit) Post(id, outcome, summary string, durationMs int64) error {
	return a.write(map[string]any{
		"ts":          auditStamp(),
		"phase":       "post",
		"decision_id": id,
		"outcome":     outcome,
		"summary":     summary,
		"duration_ms": durationMs,
	})
}
