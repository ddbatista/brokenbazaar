//go:build !vulnerable

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// GatewayExecutor is the hardened path: the agent asks the gateway to
// run a tool and never runs one itself (D5). It dials gatewayURL, which
// comes from the environment and is fixed at startup -- never from a
// model argument. That distinction is the security property: an
// attacker with total control of the document body can change what the
// agent ASKS FOR, and cannot change WHO IT ASKS.
//
// This file is compiled into the hardened binary only. The vulnerable
// build replaces it (executor_vulnerable.go), which is why the hardened
// artifact contains no NaiveExecutor symbol at all -- the check in
// Makefile's `verify-agent-builds` target asserts exactly that.
//
// The wire contract is D5.1, as amended by D5.3:
//
//	POST /gate  {"tool", "args", "session":{id,org,acting_for},
//	             "provenance":{"derived_from":[...]}}
//
//	200 {"route":"allow","decision_id","reason","text","summary"}
//	200 {"route":"deny", "decision_id","text":"gateway denied","summary":""}
//
// A decision is HTTP 200 either way -- a deny is the gateway doing its
// job, not a transport error. Denials carry NO reason on the wire
// (SR-B7-7 read against leaf B7 2.2: the reason is an existence/policy
// oracle -- an attacker who learns "resolved_address_denied" learns the
// host PASSED the allowlist, which is exactly where to point a
// rebinding attack). The reasons live in gateway.jsonl only, joined by
// decision_id.
//
// Transport failure fails CLOSED: one attempt, no retry, no fallback --
// there is no tool code in this binary to fall back to, which is D5's
// structural claim, not a policy this method enforces.
type GatewayExecutor struct {
	gatewayURL string
	client     *http.Client
}

var _ ToolExecutor = (*GatewayExecutor)(nil)

// NewExecutor is the build-tag selected constructor. Both files define
// it; only one is compiled.
//
// The hardened executor deliberately ignores cfg.Pool and cfg.OrgID: it
// has no business touching the database, and the compiler cannot
// express "holds this field but must not use it". The residual declared
// in loop.go covers the same exposure at package level.
func NewExecutor(_ ExecutorConfig) ToolExecutor {
	return &GatewayExecutor{
		gatewayURL: os.Getenv("GATEWAY_URL"),
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// NewAssembler returns the labelled, provenance-preserving assembler.
// Selected by the same build tag as the executor, so a binary cannot
// end up with a hardened executor and a naive assembler -- the two
// halves of the mode are chosen once, at compile time, together.
func NewAssembler() Assembler { return &LabelledAssembler{} }

// NewAgentAudit returns nil in hardened builds: the gateway's JSONL is
// the entire audit trail in this mode, and there is no code path that
// writes agent.jsonl from a hardened binary (D4's two-writers split,
// decided by build tag rather than by a runtime flag someone could
// forget to set).
func NewAgentAudit() (*AgentAudit, error) { return nil, nil }

// Mode names the build for startup logging. M2-N4 is the split-brain
// problem -- two processes reading HARDENED in two languages with
// nothing making them agree -- and a build that announces which binary
// it is at least makes the disagreement visible in the logs. The
// mode-agreement check itself lands in T6.
func Mode() string { return "hardened" }

// gateRequest is the /gate payload. Field set is the whole contract
// (D5.1): subject (tool, args) and platform state (session,
// provenance). Nothing testimony-shaped is sent -- no justification, no
// prior results, no self-description -- and any future field must clear
// M2-N3 before landing.
type gateRequest struct {
	Tool       string            `json:"tool"`
	Args       map[string]string `json:"args"`
	Session    SessionInfo       `json:"session"`
	Provenance gateProvenance    `json:"provenance"`
}

type gateProvenance struct {
	DerivedFrom []string `json:"derived_from"`
}

// gateResponse is the gateway's answer. Reason is present on allow only;
// a deny that carried a reason would ship the oracle the wire contract
// exists to withhold (D5.3).
type gateResponse struct {
	Route      string `json:"route"`
	DecisionID string `json:"decision_id"`
	Reason     string `json:"reason"`
	Text       string `json:"text"`
	Summary    string `json:"summary"`
}

func (e *GatewayExecutor) Execute(ctx context.Context, a Action, call CallContext) (Result, error) {
	if e.gatewayURL == "" {
		return Result{}, fmt.Errorf("gateway executor: GATEWAY_URL is not set; nothing can execute without the gate (fail closed)")
	}

	body, err := json.Marshal(gateRequest{
		Tool:       a.Tool,
		Args:       a.Args,
		Session:    call.Session,
		Provenance: gateProvenance{DerivedFrom: call.DerivedFrom},
	})
	if err != nil {
		return Result{}, fmt.Errorf("gateway executor: encoding %s call: %w", a.Tool, err)
	}

	url := strings.TrimSuffix(e.gatewayURL, "/") + "/gate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("gateway executor: building %s request: %w", a.Tool, err)
	}
	req.Header.Set("Content-Type", "application/json")

	// ONE attempt. Retries would mask outages and complicate the
	// fault-injection case that verifies fail-closed (D5.5), and there
	// is nothing to retry INTO: a gateway that did not answer once is
	// a gateway whose audit pre-record may not exist, and executing
	// past that would break D4's causality rather than just latency.
	resp, err := e.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("gateway executor: reaching the gateway: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf(
			"gateway executor: the gateway answered HTTP %d (a decision is 200; anything else is operational -- failing closed, nothing executed)",
			resp.StatusCode)
	}

	var out gateResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return Result{}, fmt.Errorf("gateway executor: decoding the gateway's decision: %w", err)
	}

	switch out.Route {
	case "allow":
		// Tool output is untrusted by default (SR-B4-7) -- including
		// read_document results from this platform's own database,
		// which is finding 03's entire premise.
		return Result{
			Tool:       a.Tool,
			Text:       out.Text,
			Summary:    out.Summary,
			Route:      "allow",
			DecisionID: out.DecisionID,
			Origin:     OriginUntrusted,
		}, nil
	case "deny":
		// The denial notice is platform speech: origin system, uniform
		// text from the wire (D5.3's amendment of T2 D3's example).
		return Result{
			Tool:       a.Tool,
			Text:       out.Text,
			Summary:    out.Summary,
			Route:      "deny",
			DecisionID: out.DecisionID,
			Origin:     OriginSystem,
		}, nil
	default:
		return Result{}, fmt.Errorf("gateway executor: unknown route %q -- failing closed", out.Route)
	}
}
