package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// The T5 loop tests: everything Run does around the executor --
// provenance computation, the tool_calls row's route/citation pairing,
// denial-origin mapping, argument redaction, and D4's audit ordering --
// provable without a database because Sessions is an interface
// (SessionRecorder). The end-to-end run against the real stack is T7.
//
// userAskNoRef is used wherever a test needs EXACTLY ONE dispatch. The
// shared userAsk in agent_test.go embeds a document UUID, which
// ScriptedModel correctly answers with a second read_document turn --
// right behaviour, and noise in a test about one call's bookkeeping.
const userAskNoRef = "Summarize our Q3 revenue breakdown."

// fakeExecutor records what the loop handed it, returns a canned Result,
// and can run a callback mid-Execute -- which is how "the pre-record
// exists before dispatch" is asserted structurally rather than by
// reading the code and nodding.
type fakeExecutor struct {
	calls []CallContext
	res   Result
	err   error
	mid   func()
}

func (f *fakeExecutor) Execute(_ context.Context, a Action, call CallContext) (Result, error) {
	f.calls = append(f.calls, call)
	if f.mid != nil {
		f.mid()
	}
	if f.err != nil {
		return Result{}, f.err
	}
	res := f.res
	res.Tool = a.Tool
	return res, nil
}

// fakeSessions satisfies SessionRecorder without a database.
type fakeSessions struct {
	transcript []store.Message
	messages   []store.Message
	calls      []store.ToolCall
}

func (f *fakeSessions) Messages(context.Context) ([]store.Message, error) {
	return f.transcript, nil
}

func (f *fakeSessions) AppendMessage(_ context.Context, m store.Message) (store.Message, error) {
	f.messages = append(f.messages, m)
	return m, nil
}

func (f *fakeSessions) AppendToolCall(_ context.Context, c store.ToolCall) (store.ToolCall, error) {
	f.calls = append(f.calls, c)
	return c, nil
}

// oneFetchTranscript is the context after read_document returned the
// poisoned document, with a user ask carrying no document reference:
// the model's only remaining action is the fetch (finding 03, turn 2).
func oneFetchTranscript() []store.Message {
	return []store.Message{
		{Role: store.MessageRoleUser, Origin: store.MessageOriginUser, Body: userAskNoRef},
		{Role: store.MessageRoleTool, Origin: store.MessageOriginUntrusted, Body: poisonedDoc},
	}
}

func newTestLoop(exec ToolExecutor, sess SessionRecorder, audit *AgentAudit) *Loop {
	return &Loop{
		Assembler:    &LabelledAssembler{},
		Model:        &ScriptedModel{},
		Executor:     exec,
		Sessions:     sess,
		SystemPrompt: sysPrompt,
		Session:      SessionInfo{ID: "s-test", OrgID: "org-test", ActingFor: "u-test"},
		Audit:        audit,
	}
}

// TestDerivedFrom is the platform-owned provenance D5.1 puts on the wire
// and D5.2 puts in the audit record. It reads Origin fields the model
// never sees and cannot touch: falsifying it requires process
// compromise, not prompt influence (M2-N3 -- the payload carries subject
// and platform state, never testimony).
func TestDerivedFrom(t *testing.T) {
	cases := []struct {
		name  string
		spans []Span
		want  string
	}{
		{
			// Turn 1 of finding 03: the user asked, nothing untrusted read yet.
			name: "user only",
			spans: []Span{
				{Origin: OriginSystem, Role: RoleSystem, Text: sysPrompt},
				{Origin: OriginUser, Role: RoleUser, Text: userAsk},
			},
			want: "user",
		},
		{
			// Turn 2: the document is in context. This is what the gate sees
			// when it denies the fetch.
			name:  "user plus untrusted",
			spans: afterRead(poisonedDoc),
			want:  "user,untrusted",
		},
		{
			// The system prompt is a constant in every call and carries no
			// per-call information, so it never appears.
			name:  "the system prompt alone contributes nothing",
			spans: []Span{{Origin: OriginSystem, Role: RoleSystem, Text: sysPrompt}},
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(DerivedFrom(tc.spans), ","); got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}

// TestNaiveAssemblerLosesProvenance is the B4 2.1 bug visible as DATA
// rather than as a merged string -- and part of why D4 wanted a second
// writer. The vulnerable build's own telemetry records an empty
// derived_from: the agent cannot say where its content came from,
// because the concatenation destroyed the per-span labels. This holds
// for the STORED transcript only; results read during the run keep
// their label (TestNaiveLoopStillLabelsInRunToolResults).
func TestNaiveAssemblerLosesProvenance(t *testing.T) {
	msgs := oneFetchTranscript()

	hardened := DerivedFrom((&LabelledAssembler{}).Assemble(sysPrompt, msgs))
	vulnerable := DerivedFrom((&NaiveAssembler{}).Assemble(sysPrompt, msgs))

	if strings.Join(hardened, ",") != "user,untrusted" {
		t.Fatalf("hardened provenance: want user,untrusted got %v", hardened)
	}
	if len(vulnerable) != 0 {
		t.Fatalf("the naive assembler should leave no provenance to report, got %v", vulnerable)
	}
	if vulnerable == nil {
		t.Fatal("empty provenance must marshal as [], never null")
	}
}

// TestNaiveLoopStillLabelsInRunToolResults pins what the vulnerable
// build's telemetry actually says about finding 03, which T9's R1 rule
// (detections/agent_rules.py, untrusted-fetch) depends on. The naive
// assembler merges the STORED transcript -- so a user-only context
// reports [] -- but a document read DURING the run is appended as its
// own untrusted tool span, so the exfiltration fetch on turn 2 reports
// ["untrusted"]. The loss is the user label, not the untrusted one.
// Found at T9 open: provenance.go's docstring claimed the turn-2 list
// was empty, which would have made R1 blind in vulnerable mode.
func TestNaiveLoopStillLabelsInRunToolResults(t *testing.T) {
	sess := &fakeSessions{transcript: []store.Message{
		{Role: store.MessageRoleUser, Origin: store.MessageOriginUser, Body: userAsk},
	}}
	exec := &fakeExecutor{res: Result{Text: poisonedDoc, Route: "unmediated"}}
	loop := newTestLoop(exec, sess, nil)
	loop.Assembler = &NaiveAssembler{}

	if _, err := loop.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("want read_document then http_fetch, got %d dispatches", len(exec.calls))
	}
	if got := exec.calls[0].DerivedFrom; len(got) != 0 {
		t.Fatalf("turn 1 (user ask merged into the system span): want [], got %v", got)
	}
	if got := strings.Join(exec.calls[1].DerivedFrom, ","); got != "untrusted" {
		t.Fatalf("turn 2 (the exfil fetch): want untrusted, got %q", got)
	}
}

// TestLoopRecordsDenialAsPlatformSpeech covers D5.3's amendment of
// T2 D3's example: the gateway's denial is uniform text carrying no
// reason, and it enters the transcript as SYSTEM origin -- the platform
// refused; a tool did not speak -- while the tool_calls row cites the
// gate's license.
func TestLoopRecordsDenialAsPlatformSpeech(t *testing.T) {
	sess := &fakeSessions{transcript: oneFetchTranscript()}
	exec := &fakeExecutor{res: Result{
		Text:       "gateway denied",
		Route:      "deny",
		DecisionID: "d_7f3a0011cc22dd33",
		Origin:     OriginSystem,
	}}

	if _, err := newTestLoop(exec, sess, nil).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	var toolMsgs []store.Message
	for _, m := range sess.messages {
		if m.Role == store.MessageRoleTool {
			toolMsgs = append(toolMsgs, m)
		}
	}
	if len(toolMsgs) != 1 {
		t.Fatalf("want one tool message, got %d", len(toolMsgs))
	}
	if toolMsgs[0].Origin != store.MessageOriginSystem {
		t.Fatalf("denial notice: want origin system (platform speech), got %q", toolMsgs[0].Origin)
	}
	if toolMsgs[0].Body != "gateway denied" {
		t.Fatalf("denial body: want the uniform text with no reason, got %q", toolMsgs[0].Body)
	}

	if len(sess.calls) != 1 {
		t.Fatalf("want one tool_calls row, got %d", len(sess.calls))
	}
	tc := sess.calls[0]
	if tc.Route != store.ToolRouteDeny {
		t.Fatalf("tool_calls route: want deny, got %q", tc.Route)
	}
	if tc.DecisionID == nil || *tc.DecisionID != "d_7f3a0011cc22dd33" {
		t.Fatalf("a mediated row must cite the gate's license, got %v", tc.DecisionID)
	}

	if len(exec.calls) != 1 {
		t.Fatalf("want one dispatch, got %d", len(exec.calls))
	}
	if got := strings.Join(exec.calls[0].DerivedFrom, ","); got != "user,untrusted" {
		t.Fatalf("provenance handed to the executor: want user,untrusted got %q", got)
	}
	s := exec.calls[0].Session
	if s.ID != "s-test" || s.OrgID != "org-test" || s.ActingFor != "u-test" {
		t.Fatalf("session context handed to the executor: %+v", s)
	}
}

// TestLoopAllowedResultIsUntrusted: SR-B4-7 has no "it came from our own
// database" exemption -- that exemption is finding 03's entire premise.
func TestLoopAllowedResultIsUntrusted(t *testing.T) {
	sess := &fakeSessions{transcript: oneFetchTranscript()}
	exec := &fakeExecutor{res: Result{
		Text:       "Acme Corp - Q3 revenue breakdown",
		Summary:    "Acme Corp - Q3 revenue breakdown (1420 bytes)",
		Route:      "allow",
		DecisionID: "d_9c2e44aa55bb66cc",
		Origin:     OriginUntrusted,
	}}

	if _, err := newTestLoop(exec, sess, nil).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sess.messages[0].Origin != store.MessageOriginUntrusted {
		t.Fatalf("allowed tool output must enter as untrusted, got %q", sess.messages[0].Origin)
	}
	if sess.calls[0].ResultSummary == nil || *sess.calls[0].ResultSummary == "" {
		t.Fatal("the tool_calls row should carry the short summary")
	}
}

// TestLoopRecordsUnmediatedCallWithAuditOrdering is D4's ordering as a
// structural assertion: mid-dispatch, the pre-record is already durable
// on disk. A loop that recorded after execution fails here, and no
// amount of reading the code substitutes for the check.
func TestLoopRecordsUnmediatedCallWithAuditOrdering(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit", "agent.jsonl")
	audit, err := openAgentAudit(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}

	sess := &fakeSessions{transcript: oneFetchTranscript()}
	exec := &fakeExecutor{res: Result{Text: "200 OK", Route: "unmediated"}}
	exec.mid = func() {
		data, rerr := os.ReadFile(auditPath)
		if rerr != nil {
			t.Errorf("mid-dispatch: audit file unreadable: %v", rerr)
			return
		}
		if !strings.Contains(string(data), `"phase":"pre"`) {
			t.Errorf("mid-dispatch: no pre-record on disk -- D4 ordering is broken:\n%s", data)
		}
		if !strings.Contains(string(data), `"tool":"http_fetch"`) {
			t.Errorf("mid-dispatch: the pre-record does not name the tool:\n%s", data)
		}
	}

	if _, err := newTestLoop(exec, sess, audit).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want exactly a pre and a post line, got %d:\n%s", len(lines), data)
	}

	var pre, post map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &pre); err != nil {
		t.Fatalf("pre line is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &post); err != nil {
		t.Fatalf("post line is not JSON: %v", err)
	}

	// SR-B5-9: the vulnerable mode is not silent, and it does not claim a
	// decision nobody made.
	if pre["phase"] != "pre" || pre["route"] != "unmediated" || pre["mediated"] != false {
		t.Fatalf("pre record: %+v", pre)
	}
	if pre["reasons"] != nil {
		t.Fatalf("an unmediated call has no reasons to report, got %v", pre["reasons"])
	}
	// SR-B3-9: every record carries session and acting_for.
	if pre["session"] != "s-test" || pre["acting_for"] != "u-test" || pre["org"] != "org-test" {
		t.Fatalf("pre record attribution: %+v", pre)
	}
	prov, ok := pre["provenance"].(map[string]any)
	if !ok || fmt.Sprint(prov["derived_from"]) != "[user untrusted]" {
		t.Fatalf("pre record provenance: %+v", pre["provenance"])
	}
	// Agent-minted ids are a_-prefixed; only d_ ids ever reach the DB's
	// citation column.
	id, _ := pre["decision_id"].(string)
	if !strings.HasPrefix(id, "a_") {
		t.Fatalf("agent-minted id must be a_-prefixed, got %q", id)
	}
	if post["phase"] != "post" || post["outcome"] != "ok" || post["decision_id"] != id {
		t.Fatalf("the post record must join to the pre record: %+v", post)
	}

	tc := sess.calls[0]
	if tc.Route != store.ToolRouteUnmediated || tc.DecisionID != nil {
		t.Fatalf("unmediated row: want route unmediated with a NULL citation, got route=%q id=%v", tc.Route, tc.DecisionID)
	}
}

// TestUnwritableAuditPathFailsAtConstruction: an audit destination that
// cannot be written is a startup failure, not a mid-run surprise.
func TestUnwritableAuditPathFailsAtConstruction(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	audit, err := openAgentAudit(filepath.Join(blocker, "nested", "agent.jsonl"))
	if err == nil {
		t.Fatal("a path under a regular file must fail at open")
	}
	if audit != nil {
		t.Fatal("a failed open must return a nil writer, never a half-built one")
	}
}

// TestLoopAuditFailureRefusesTheCall is SR-B5-6 enforced by ordering:
// no record, no execution. The executor must never be reached.
//
// The failure is injected by replacing the audit file with a DIRECTORY
// after construction -- OpenFile(O_WRONLY) on a directory is EISDIR even
// for root, which a chmod-based test would NOT achieve in a container
// that runs as root (the first draft of this test did exactly that and
// would have passed vacuously).
func TestLoopAuditFailureRefusesTheCall(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "agent.jsonl")
	audit, err := openAgentAudit(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(auditPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(auditPath, 0o755); err != nil {
		t.Fatal(err)
	}

	sess := &fakeSessions{transcript: oneFetchTranscript()}
	exec := &fakeExecutor{res: Result{Text: "200 OK", Route: "unmediated"}}

	_, runErr := newTestLoop(exec, sess, audit).Run(context.Background())
	if runErr == nil {
		t.Fatal("a failed pre-record must fail the run")
	}
	if !strings.Contains(runErr.Error(), "audit pre-record") {
		t.Fatalf("the error should name the audit failure, got: %v", runErr)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("the executor ran %d time(s) past a failed pre-record -- SR-B5-6 violated", len(exec.calls))
	}
	if len(sess.calls) != 0 {
		t.Fatalf("a refused call must not produce a tool_calls row, got %d", len(sess.calls))
	}
}

// TestLoopRedactsArgumentsInEveryStore is MCP01's coverage half at the
// loop level: a credential-named argument must reach neither the DB row
// nor the JSONL. ScriptedModel would never emit one; a RemoteModel under
// attacker influence is exactly the case this guards, so the fake models
// it directly.
func TestLoopRedactsArgumentsInEveryStore(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "agent.jsonl")
	audit, err := openAgentAudit(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	// A deliberately inert fake value: this test asserts on field NAMES,
	// which is the whole of M2-N2, so the value never needs to resemble a
	// real credential.
	const fakeValue = "tok-TESTVALUE-0001"
	calls := 0
	injecting := modelFunc(func(_ []Span) Action {
		calls++
		if calls > 1 {
			return Action{Answer: "done"}
		}
		return Action{Tool: "http_fetch", Args: map[string]string{
			"url":           "http://docs.example/a?token=" + fakeValue,
			"session_token": fakeValue,
		}}
	})

	sess := &fakeSessions{transcript: oneFetchTranscript()}
	exec := &fakeExecutor{res: Result{Text: "ok", Route: "unmediated"}}
	loop := newTestLoop(exec, sess, audit)
	loop.Model = injecting

	if _, err := loop.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	args := sess.calls[0].Arguments
	if strings.Contains(args, `"session_token":"`+fakeValue) {
		t.Fatalf("the credential-named field reached the tool_calls row: %s", args)
	}
	if !strings.Contains(args, "[REDACTED]") {
		t.Fatalf("no redaction happened at all: %s", args)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"session_token":"`+fakeValue) {
		t.Fatalf("the credential-named field reached agent.jsonl:\n%s", data)
	}

	// The declared residual, pinned here as it is in redact_test.go: the
	// same value inside the URL VALUE survives, because redaction is by
	// field name and never by value shape (M2-N2). This assertion exists
	// so a future change that starts mangling URLs fails a test and
	// forces a conscious re-declaration -- URL mangling would also blind
	// T9, which reads urls out of the audit store.
	if !strings.Contains(string(data), "token="+fakeValue) {
		t.Fatalf("the declared residual changed: a token inside a URL should survive:\n%s", data)
	}
}

// modelFunc adapts a function to Model, for tests that need a model
// ScriptedModel deliberately cannot be.
type modelFunc func(spans []Span) Action

func (f modelFunc) Next(spans []Span) Action { return f(spans) }
