//go:build vulnerable

package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// NaiveExecutor is the planted bug's home. Three leaves live in this
// one file, and they are different failures that happen to share a
// struct:
//
//	B5 2.1  "a built-in or first-party tool bypasses the gateway
//	         because it is 'internal'"
//	B5 3.2  "allow/deny on the tool name alone, ignoring arguments"
//	B5 4.3  "TOCTOU -- the argument is re-resolved after the decision"
//
// This file is compiled into the vulnerable binary ONLY. That is the
// whole of D5: mediation is enforced by what code exists where, not by
// a check that remembers to run. There is no build of this program in
// which both this type and the hardened path are reachable.
//
// DO NOT "fix" anything here -- it is the deliverable (AGENTS.md). The
// hardened implementations are gateway/tools/fetch.py and
// gateway/tools/documents.py, written first, per the house rule.
type NaiveExecutor struct {
	cfg ExecutorConfig
}

var _ ToolExecutor = (*NaiveExecutor)(nil)

// NewExecutor is the build-tag selected constructor. Both files define
// it; only one is compiled.
func NewExecutor(cfg ExecutorConfig) ToolExecutor { return &NaiveExecutor{cfg: cfg} }

// NewAssembler returns the naive concatenating assembler -- the planted
// B4 2.1 bug. Selected by the same build tag as the executor: the two
// halves of the mode are chosen once, at compile time, together.
func NewAssembler() Assembler { return &NaiveAssembler{} }

// Mode names the build for startup logging. See the hardened file.
func Mode() string { return "vulnerable" }

// NewAgentAudit opens D4's second writer for this build. The hardened
// file's version returns nil: over THERE the gateway's JSONL is the
// whole audit trail, and no hardened binary contains a code path that
// writes agent.jsonl. Here, the agent is the only writer there is --
// nothing mediated these calls, so nothing else can record them, and an
// unrecorded vulnerable mode would be silent (SR-B5-9).
//
// The path is AGENT_AUDIT_PATH or audit/agent.jsonl beside the
// gateway's audit/gateway.jsonl, so one volume mounts both (T6).
func NewAgentAudit() (*AgentAudit, error) {
	path := os.Getenv("AGENT_AUDIT_PATH")
	if path == "" {
		path = defaultAgentAuditPath
	}
	return openAgentAudit(path)
}

// naiveAllowedTools is leaf B5 3.2: a check that exists and is
// worthless. §2 describes it as "vulnerable mode's mechanical check,
// WHERE IT EXISTS AT ALL" -- the tool NAME is allowlisted and the
// arguments are never looked at. http_fetch is permitted, so every URL
// is permitted. It passes code review ("we validate the tool name")
// and constrains nothing an attacker cares about.
var naiveAllowedTools = map[string]bool{
	"read_document": true,
	"http_fetch":    true,
}

func (e *NaiveExecutor) Execute(ctx context.Context, a Action, _ CallContext) (Result, error) {
	// B5 2.1, the module's planted bug: the gateway is never consulted.
	// Not asked and denied -- not asked at all. There is no POST to
	// /gate anywhere in this file, because "it's internal, so it's
	// fine."
	if !naiveAllowedTools[a.Tool] {
		return Result{}, fmt.Errorf("agent: unknown tool %q", a.Tool)
	}

	switch a.Tool {
	case "read_document":
		return e.readDocument(ctx, a.Args["id"])
	case "http_fetch":
		return e.httpFetch(ctx, a.Args["url"])
	default:
		return Result{}, fmt.Errorf("agent: unroutable tool %q", a.Tool)
	}
}

// readDocument runs in-process, against the session's own org.
//
// Note what is NOT wrong here: tenancy. The store is scoped with
// ForOrg(session org), so this returns only the acting org's documents.
// That is deliberate (T4 D2). M2's planted bug is "the gateway was
// bypassed", not "the wrong tenant's data came back" -- using
// NaiveStore would re-plant finding 01 inside finding 03, and the
// writeup could no longer say which gap caused the exfiltration.
// Keeping tenancy correct isolates the variable under test.
//
// What IS wrong: nothing mediated this. In hardened mode the same read
// goes agent -> gateway -> API internal route -> ForOrg, authenticated
// by a service secret the agent does not hold (D5b). Here the agent
// simply holds a database pool.
func (e *NaiveExecutor) readDocument(ctx context.Context, id string) (Result, error) {
	if id == "" {
		return Result{}, fmt.Errorf("agent: read_document requires an id")
	}
	doc, found, err := store.ForOrg(e.cfg.Pool, e.cfg.OrgID).Get(ctx, id)
	if err != nil {
		return Result{}, fmt.Errorf("agent: read_document %s: %w", id, err)
	}
	if !found {
		return Result{}, fmt.Errorf("agent: no document %s readable in org %s", id, e.cfg.OrgID)
	}
	// Title and body together: the body carries the injected
	// instruction. SR-B4-7 says tool output is untrusted by default, and
	// the loop labels this span untrusted in BOTH modes -- ingestion
	// labelling is not the planted bug (T3 D3).
	//
	// Route is "unmediated" (T5): no decision was made, and recording
	// "allow" would claim one was. The loop pairs it with a NULL
	// decision_id via the schema's CHECK.
	text := doc.Title + "\n\n" + doc.Body
	return Result{
		Tool:    "read_document",
		Text:    text,
		Summary: fmt.Sprintf("%s (%d bytes)", doc.Title, len(text)),
		Route:   "unmediated",
	}, nil
}

// httpFetch is the mirror image of gateway/tools/fetch.py, and the
// entire difference between them is that this one is short.
//
// B5 4.3 / B7 1.2, and the reason SR-B5-3 exists: http.Client resolves
// the hostname inside its own dial, so even if something upstream had
// checked an address, THIS lookup is the one that executes. There is no
// allowlist, no range check, and the client follows up to 10 redirects
// by default -- each hop re-resolved, none re-evaluated, because there
// is nothing here to re-evaluate with.
//
// This is not a strawman. It is what a competent developer writes when
// nobody has told them the resolved value has to be the executed one.
func (e *NaiveExecutor) httpFetch(ctx context.Context, rawURL string) (Result, error) {
	if rawURL == "" {
		return Result{}, fmt.Errorf("agent: http_fetch requires a url")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("agent: http_fetch %s: %w", rawURL, err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("agent: http_fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Result{}, fmt.Errorf("agent: http_fetch %s: reading body: %w", rawURL, err)
	}

	// The final URL after redirects, which may be nothing like the one
	// that was (not) evaluated. Recorded so the PoC can print the hop
	// the agent actually reached -- B7 1.2's redirect variant is what
	// makes finding 04 more than a string-match demo.
	final := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}

	text := strings.TrimSpace(string(body))
	return Result{
		Tool:    "http_fetch",
		Text:    text,
		Summary: fmt.Sprintf("%s -> %d (%d bytes)", final, resp.StatusCode, len(text)),
		Route:   "unmediated",
	}, nil
}
