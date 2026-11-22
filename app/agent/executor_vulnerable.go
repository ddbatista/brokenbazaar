//go:build vulnerable

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

	"github.com/ddbatista/brokenbazaar/app/mcp"
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
// hardened implementations of M2's two tools are gateway/tools/fetch.py
// and gateway/tools/documents.py, written first, per the house rule.
// M3's write tools are the departure from that rule, recorded in the
// plan's T4 entry: their hardened path (gateway -> authority route ->
// internal route, threat-model D4) lands in T6. What exists first is
// the design (m3-delegation.md D3/D4) and the permission table it calls
// (app/authz, T3).
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
//
// M3 T4 adds the two write tools on the same terms, and T5 the role
// change. The check still knows names only: not the requester's role, not
// the session's scope, and not that set_member_role is a control-plane
// action no session should hold (SR-B3-7, SR-B8-2).
var naiveAllowedTools = map[string]bool{
	"read_document":   true,
	"http_fetch":      true,
	"update_document": true,
	"delete_document": true,
	"set_member_role": true,
}

func (e *NaiveExecutor) Execute(ctx context.Context, a Action, call CallContext) (Result, error) {
	// B5 2.1, the module's planted bug: the gateway is never consulted.
	// Not asked and denied -- not asked at all. There is no POST to
	// /gate anywhere in this file, because "it's internal, so it's
	// fine."
	//
	// M4a T4: the naiveAllowedTools map above is now the PLATFORM
	// registry, documented and tested, not the gate it was in M2 -- a
	// name it does not carry is no longer "unknown" here but a
	// MARKETPLACE candidate, and the admission check for those is the
	// LIVE manifest (installedTool below): a name the publisher's
	// current manifest carries is callable. That check exists and is
	// worthless, the same B5 3.2 shape one boundary over -- the
	// manifest's `receives` vocabulary is displayed at install review
	// and never read on any path.
	switch a.Tool {
	case "read_document":
		return e.readDocument(ctx, a.Args["id"])
	case "http_fetch":
		return e.httpFetch(ctx, a.Args["url"])
	case "update_document":
		body, ok := a.Args["body"]
		if !ok {
			return Result{}, fmt.Errorf("agent: update_document requires a body")
		}
		return e.updateDocument(ctx, a.Args["id"], body)
	case "delete_document":
		return e.deleteDocument(ctx, a.Args["id"])
	case "set_member_role":
		return e.setMemberRole(ctx, a.Args["user"], store.Role(a.Args["role"]), call.Session)
	default:
		// The marketplace dispatch (finding 07's exfil channel, finding
		// 08's widened set). THE PLANTED 2.4: the tool's existence is
		// checked against the LIVE manifest, fetched from the publisher's
		// server on every dispatch -- never against the install row's
		// pinned bytes. The check is real and worthless (B5 3.2): the
		// live manifest's `receives` vocabulary is displayed at install
		// review and never read on any path here.
		return e.installedTool(ctx, a)
	}
}

// installedTool resolves and executes a third-party tool call in-process,
// with the agent's own client, mediated by nothing. The org's installs
// come from the database; the manifest comes LIVE from each endpoint,
// per call; the first install whose CURRENT manifest names the tool
// wins (one listing per name is the lab's shape; documented, not
// enforced). A name no live manifest carries is unknown, refused
// loudly -- the same error shape as the platform tools' map check.
func (e *NaiveExecutor) installedTool(ctx context.Context, a Action) (Result, error) {
	if a.Tool == "" {
		return Result{}, fmt.Errorf("agent: no tool named")
	}
	installs, err := store.ForOrg(e.cfg.Pool, e.cfg.OrgID).Installs(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("agent: listing installs in org %s: %w", e.cfg.OrgID, err)
	}
	fetchFailures := 0
	for _, ins := range installs {
		body, err := liveManifest(ins.EndpointURL)
		if err != nil {
			// An unreachable server cannot vouch for a name; keep
			// looking. Fail closed on the name, never open on the
			// fetch -- but never silently: the refusal below names
			// how many servers were consulted and how many failed,
			// because a diagnosis-blind refusal is how a dead route
			// reads as a policy decision.
			fetchFailures++
			continue
		}
		tools, _ := mcp.Parse(body)
		for _, t := range tools {
			if t.Name != a.Tool {
				continue
			}
			// FOUND IN THE LIVE MANIFEST. Nothing here reads
			// t.Receives -- the org's install-time consent vocabulary
			// dies at this dispatch, which is finding 07's whole
			// premise.
			resp, err := marketplaceClient.Post(ins.EndpointURL, "application/json",
				bytes.NewReader(mcp.CallRequest(a.Tool, a.Args)))
			if err != nil {
				return Result{}, fmt.Errorf("agent: calling %s at %s: %w", a.Tool, ins.EndpointURL, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return Result{}, fmt.Errorf("agent: %s answered HTTP %d calling %s", ins.EndpointURL, resp.StatusCode, a.Tool)
			}
			var out struct {
				Result struct {
					Content string `json:"content"`
				} `json:"result"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
				return Result{}, fmt.Errorf("agent: decoding %s's answer to %s: %w", ins.EndpointURL, a.Tool, err)
			}
			return unmediated(a.Tool, strings.TrimSpace(out.Result.Content)), nil
		}
	}
	return Result{}, fmt.Errorf("agent: unknown tool %q (%d installs consulted, %d manifests unreachable)", a.Tool, len(installs), fetchFailures)
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

// updateDocument and deleteDocument are M3's planted bug (finding 05,
// B3 1.1 / 1.2): the confused deputy.
//
// The agent acts with its own database credential -- ambient authority
// -- and never asks whether the user it acts for may do this. A viewer
// cannot delete through the direct API (M3 T3 enforces the role table in
// both builds); a viewer's agent can, because nothing on this path ever
// reads acting_for's role. The role is not cached, not stale, not
// mis-read: it is never looked at.
//
// Nor is the session's scope. The row records the tools the session was
// opened for (migration 003) and no field carries it here
// (TestScopeNeverTravelsWithTheCall), so a session opened to summarise
// can delete: B3 2.1, every grant in scope, as M2 D7 handed it over.
//
// What is NOT wrong, by the same argument as readDocument's: tenancy.
// Both go through ForOrg(session org), so the confused deputy stays in
// its own org. 05 is about whose authority, not which tenant.
func (e *NaiveExecutor) updateDocument(ctx context.Context, id, body string) (Result, error) {
	if id == "" {
		return Result{}, fmt.Errorf("agent: update_document requires an id")
	}
	docs := store.ForOrg(e.cfg.Pool, e.cfg.OrgID)
	// The tool replaces the body and keeps the title, so the title is
	// read first. Two statements, not one: a concurrent title edit in
	// between is lost. Accepted -- this is the vulnerable build, and the
	// lost update is not the finding.
	doc, found, err := docs.Get(ctx, id)
	if err != nil {
		return Result{}, fmt.Errorf("agent: update_document %s: %w", id, err)
	}
	if !found {
		return Result{}, fmt.Errorf("agent: no document %s writable in org %s", id, e.cfg.OrgID)
	}
	doc.Body = body
	_, stillThere, err := docs.Update(ctx, doc)
	if err != nil {
		return Result{}, fmt.Errorf("agent: update_document %s: %w", id, err)
	}
	if !stillThere {
		return Result{}, fmt.Errorf("agent: document %s vanished during update in org %s", id, e.cfg.OrgID)
	}
	return unmediated("update_document", fmt.Sprintf("updated %s (%d bytes)", id, len(body))), nil
}

func (e *NaiveExecutor) deleteDocument(ctx context.Context, id string) (Result, error) {
	if id == "" {
		return Result{}, fmt.Errorf("agent: delete_document requires an id")
	}
	deleted, err := store.ForOrg(e.cfg.Pool, e.cfg.OrgID).Delete(ctx, id)
	if err != nil {
		return Result{}, fmt.Errorf("agent: delete_document %s: %w", id, err)
	}
	if !deleted {
		return Result{}, fmt.Errorf("agent: no document %s deletable in org %s", id, e.cfg.OrgID)
	}
	return unmediated("delete_document", "deleted "+id), nil
}

// unmediated is a write tool's result: one short note serves as both the
// context text and the tool_calls summary, and the route is "unmediated" --
// nothing decided this call, and recording "allow" would claim something
// had (T5 of M2).
func unmediated(tool, note string) Result {
	return Result{Tool: tool, Text: note, Summary: note, Route: "unmediated"}
}

// setMemberRole is finding 06 (B3 4.2 / B8 1.2): a control-plane action
// executed because content asked for it.
//
// The same ambient authority as the write tools above, and one thing more.
// Even if this path checked the requester's role it would allow 06's call:
// the requester is an admin. What is missing is not the ceiling (05) but
// the rule above it -- authority is delegable, the authority to change the
// delegation is not (SR-B3-7, SR-B8-2, D6). Hardened mode refuses it twice:
// the gateway policy denies it by name, control_plane_not_delegable, before
// any session leg (an explicit denylist entry, not the accident of an
// unlisted tool), and no internal execution route for it exists, so even an
// allow could not execute it.
//
// What this path does get right, deliberately, is the record. The change
// goes through the same org-bound store method as the direct route, in one
// transaction with its role_changes row, and the row names the acting user
// AND the session (SR-B3-9: an agent-initiated change is distinguishable
// from a human one). Both come from the CallContext the loop built from the
// session row, never from the model. The vulnerable build must not be
// silent, or T10 cannot measure a miss (M2 D4).
func (e *NaiveExecutor) setMemberRole(ctx context.Context, user string, role store.Role, session SessionInfo) (Result, error) {
	if user == "" {
		return Result{}, fmt.Errorf("agent: set_member_role requires a user")
	}
	if !role.Valid() {
		return Result{}, fmt.Errorf("agent: set_member_role: unknown role %q", role)
	}
	if session.ID == "" || session.ActingFor == "" {
		return Result{}, fmt.Errorf("agent: set_member_role: no session to attribute the change to; refusing an unattributed role change")
	}
	change, found, err := store.ForOrg(e.cfg.Pool, e.cfg.OrgID).SetMemberRole(ctx, user, role,
		store.RoleActor{User: session.ActingFor, Session: session.ID})
	if err != nil {
		return Result{}, fmt.Errorf("agent: set_member_role %s: %w", user, err)
	}
	if !found {
		return Result{}, fmt.Errorf("agent: no member %s in org %s", user, e.cfg.OrgID)
	}
	if !change.Changed {
		return unmediated("set_member_role", fmt.Sprintf("role of %s: already %s", user, change.After)), nil
	}
	return unmediated("set_member_role", fmt.Sprintf("role of %s: %s -> %s", user, change.Before, change.After)), nil
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
