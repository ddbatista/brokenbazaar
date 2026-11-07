package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/redact"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// Result is what a tool returns. Text is the full result (it becomes a
// transcript row and a context span); Summary is the short note recorded
// on the tool_calls row, where the full bytes deliberately do not go --
// tenant data is stored once, in messages, where the context comes from.
//
// Three T5 fields extend it, all carrying gate vocabulary (D5.1/D5.2):
//
//	Route       "allow" | "deny" | "unmediated" -- what happened at the
//	            gate. The gateway executor fills it from the wire; the
//	            naive executor stamps "unmediated", the third honest
//	            outcome (T2 D3).
//	DecisionID  the gateway's d_-prefixed citation, set iff mediated. An
//	            empty string writes NULL in tool_calls, which the schema
//	            CHECK pairs with route 'unmediated'.
//	Origin      the trust class of this RESULT as a context span. Tool
//	            output is untrusted by default (SR-B4-7); the gateway's
//	            denial notice is platform speech and arrives as system
//	            (D5.3's amendment of T2 D3's example). Empty means
//	            untrusted -- the safe default, never an upgrade.
type Result struct {
	Tool       string
	Text       string
	Summary    string
	Route      string
	DecisionID string
	Origin     Origin
}

// SessionInfo is the platform context a call executes inside. The loop
// holds it once (from the session row the caller loaded) and every
// dispatch and audit record carries the same values -- provenance and
// attribution are computed by platform code, never supplied by the model
// (M2-N3: the payload may carry subject and platform state, never
// testimony).
type SessionInfo struct {
	ID        string `json:"id"`
	OrgID     string `json:"org"`
	ActingFor string `json:"acting_for"`
}

// CallContext is everything the platform knows about one dispatch,
// assembled by the loop and passed to the executor: the session the call
// acts inside, and the provenance derived from the context that produced
// the action (see DerivedFrom).
type CallContext struct {
	Session     SessionInfo
	DerivedFrom []string
}

// ExecutorConfig carries what an executor might need to construct
// itself. Both build-tagged constructors take it; each uses only what
// its mode legitimately requires.
//
// The hardened executor uses NONE of it -- it reads GATEWAY_URL from
// the environment and holds no database handle, because D5 says the
// hardened agent has no tool code and a pool is the raw material of
// one. The vulnerable executor uses Pool and OrgID to read documents
// in-process, which is the planted bypass (B5 2.1).
//
// A shared struct rather than per-mode signatures: the loop wiring in
// cmd/agent must compile identically under both tags, and the moment
// the two constructors take different arguments, main.go needs its own
// build-tagged copy -- which is exactly the duplicated wiring that
// decision 4 rejected option C for.
type ExecutorConfig struct {
	Pool      *pgxpool.Pool
	OrgID     string
	SessionID string
}

// ToolExecutor is the seam D5 is a statement about. The loop holds this
// interface and never dials anything itself.
//
// Two implementations exist, in build-tagged files, and ONLY ONE IS
// COMPILED into any given binary:
//
//	executor_hardened.go    //go:build !vulnerable   GatewayExecutor
//	executor_vulnerable.go  //go:build vulnerable    NaiveExecutor
//
// That is the difference between D5's claim and a decorator. A runtime
// `if hardened { ... } else { ... }` would leave the naive fetcher
// compiled into the hardened binary -- not immediately exploitable
// (prompt influence cannot flip an env-var selection), but it would make
// D5's stated property ("there is no http_fetch code in the binary to
// route around") false as written, and leave nothing to verify. With
// build tags the property is mechanically checkable:
//
//	go tool nm agent-hardened   | grep -c NaiveExecutor   -> 0
//	go tool nm agent-vulnerable | grep -c NaiveExecutor   -> 1
//
// One precision, so the claim is not overstated: the hardened agent
// still links net/http -- it POSTs to the gateway. The property is not
// "no HTTP", it is "no code that dials an address the model chose". The
// gateway client dials a configured URL from the environment; a naive
// fetcher dials whatever lands in Args["url"]. Only the second is an
// SSRF primitive under prompt control.
type ToolExecutor interface {
	Execute(ctx context.Context, a Action, call CallContext) (Result, error)
}

// SessionRecorder is the session-plane surface the loop needs. It exists
// as an interface because T5 gives the loop recording logic worth testing
// without a database -- origin mapping for denials, the tool_calls row's
// route/citation pairing, audit ordering -- and *store.SessionStore
// satisfies it unchanged. This is NOT the one-implementation ceremony
// session.go's comment rejects: there are two implementations, the real
// store and the test fake, and the second one exists to assert properties
// the stack tests only reach in T7.
type SessionRecorder interface {
	Messages(ctx context.Context) ([]store.Message, error)
	AppendMessage(ctx context.Context, msg store.Message) (store.Message, error)
	AppendToolCall(ctx context.Context, call store.ToolCall) (store.ToolCall, error)
}

var _ SessionRecorder = (*store.SessionStore)(nil)

// Loop is the agent loop: assemble, ask the model, dispatch, record,
// repeat.
//
// Residual, declared rather than discovered later: this package imports
// store, and store exports ForOrg -- so code in this package COULD read
// documents directly, bypassing D5b's service-secret mediation entirely.
// No such code path exists, and prompt influence cannot create one: an
// attacker who controls the document body has no way to make the loop
// call ForOrg. The exposure is therefore compromise-level, the same
// severity as M2-N1's shared bridge network, and it is code discipline
// rather than structure that keeps it closed. The session plane is the
// only thing this loop legitimately touches; the document plane reaching
// it is the raw-pool rot finding from M1's T9 audit arriving for real.
type Loop struct {
	Assembler    Assembler
	Model        Model
	Executor     ToolExecutor
	Sessions     SessionRecorder
	SystemPrompt string
	MaxTurns     int

	// Session is the platform context every dispatch carries (T5). Set
	// once by the caller from the session row; never derived from
	// anything the model produced.
	Session SessionInfo

	// Audit is D4's second writer, constructed only in vulnerable builds
	// (NewAgentAudit is build-tagged: nil in hardened, where the
	// gateway's JSONL is the entire audit trail). Nil means every audit
	// step below is skipped -- there is no code path that writes
	// agent.jsonl from a hardened binary.
	Audit *AgentAudit
}

// Outcome is what one Run produced, for the caller to print and for the
// attack harness to assert on.
type Outcome struct {
	Answer  string
	Actions []Action // every action the model produced, in order
	Turns   int
}

// Run drives the loop for one session.
//
// Context assembly happens ONCE from the stored transcript; tool results
// are then appended in memory for the remainder of the run and persisted
// as they go. The in-memory spans are what carry the Tool field (which
// the messages table does not store) and the correct per-span labels,
// so SR-B4-4's stickiness holds across turns within a run without
// depending on a re-read.
func (l *Loop) Run(ctx context.Context) (Outcome, error) {
	var out Outcome

	msgs, err := l.Sessions.Messages(ctx)
	if err != nil {
		return out, fmt.Errorf("agent: loading transcript: %w", err)
	}
	spans := l.Assembler.Assemble(l.SystemPrompt, msgs)

	maxTurns := l.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 6
	}

	for turn := 1; turn <= maxTurns; turn++ {
		out.Turns = turn
		action := l.Model.Next(spans)
		out.Actions = append(out.Actions, action)

		if !action.IsTool() {
			// SR-B4-4: the answer inherits the lowest trust of the
			// context that produced it. An answer derived from a
			// poisoned document is itself untrusted -- leaf B4 3.1,
			// recorded in the data even though M2's loop cannot
			// exploit it (the run ends here and sessions do not
			// resume).
			origin := storeOrigin(LowestTrust(spans))
			if _, err := l.Sessions.AppendMessage(ctx, store.Message{
				Role:   store.MessageRoleAssistant,
				Origin: origin,
				Body:   action.Answer,
			}); err != nil {
				return out, fmt.Errorf("agent: recording answer: %w", err)
			}
			out.Answer = action.Answer
			return out, nil
		}

		// T5: provenance is computed here, by platform code, from the
		// spans the assembler produced -- never from anything the model
		// said. The gate consumes it as a fact; see DerivedFrom.
		call := CallContext{Session: l.Session, DerivedFrom: DerivedFrom(spans)}

		// D4: in vulnerable builds the loop pre-records its own call
		// before dispatch. A pre-record that cannot be written is a
		// refused call, not a call that proceeds unrecorded --
		// SR-B5-6's "no record, no execution", enforced by ordering
		// right here rather than by a reviewer's memory.
		var auditID string
		if l.Audit != nil {
			var err error
			auditID, err = l.Audit.Pre(action, call)
			if err != nil {
				return out, fmt.Errorf("agent: audit pre-record for %s: %w", action.Tool, err)
			}
		}

		start := time.Now()
		res, execErr := l.Executor.Execute(ctx, action, call)

		// The completion record is written for failures too -- an
		// attempted call that errored is exactly the event an
		// investigator wants pre and post of.
		if l.Audit != nil {
			outcome := "ok"
			if execErr != nil {
				outcome = "error"
			}
			if err := l.Audit.Post(auditID, outcome, res.Summary, time.Since(start).Milliseconds()); err != nil {
				return out, fmt.Errorf("agent: audit post-record for %s: %w", action.Tool, err)
			}
		}
		if execErr != nil {
			// The hardened executor returns an error only for transport
			// failure -- gateway unreachable, non-200, malformed wire
			// (D5.1: fail closed, one attempt, no retry). There is no
			// fallback: nothing in this binary can execute the call.
			return out, fmt.Errorf("agent: executing %s: %w", action.Tool, execErr)
		}

		// The tool_calls row: the agent's transcript with citation
		// (T2 D3). Arguments are redacted before they reach ANY store
		// (D5.4: "never reaches any store" includes this one), and the
		// route/citation pairing the schema CHECKs is filled from the
		// executor's Result -- the vocabulary the gate, the JSONL and
		// this table share by construction.
		redactedArgs, err := json.Marshal(redact.Fields(action.Args))
		if err != nil {
			return out, fmt.Errorf("agent: encoding %s arguments: %w", action.Tool, err)
		}
		tc := store.ToolCall{
			ToolName:  action.Tool,
			Arguments: string(redactedArgs),
			Route:     store.ToolRoute(res.Route),
		}
		if res.DecisionID != "" {
			tc.DecisionID = &res.DecisionID
		}
		if res.Summary != "" {
			tc.ResultSummary = &res.Summary
		}
		if _, err := l.Sessions.AppendToolCall(ctx, tc); err != nil {
			return out, fmt.Errorf("agent: recording %s tool call: %w", action.Tool, err)
		}

		// Origin mapping for the result-as-context: SR-B4-7 default is
		// untrusted (there is no "it came from our own database"
		// exemption -- that is finding 03's entire premise); the
		// gateway's denial notice is the one result that is platform
		// speech (D5.3): uniform "gateway denied", origin system, so a
		// denied run's context shows the platform refused, not that a
		// tool spoke.
		origin := res.Origin
		if origin == "" {
			origin = OriginUntrusted
		}
		if _, err := l.Sessions.AppendMessage(ctx, store.Message{
			Role:   store.MessageRoleTool,
			Origin: storeOrigin(origin),
			Body:   res.Text,
		}); err != nil {
			return out, fmt.Errorf("agent: recording %s result: %w", action.Tool, err)
		}
		spans = append(spans, Span{
			Origin: origin,
			Role:   RoleTool,
			Tool:   res.Tool,
			Text:   res.Text,
		})
	}

	return out, fmt.Errorf("agent: reached max turns (%d) without an answer", maxTurns)
}

// storeOrigin maps back to the store vocabulary. Total and lossless, the
// same way originOf is in the other direction.
func storeOrigin(o Origin) store.MessageOrigin {
	switch o {
	case OriginSystem:
		return store.MessageOriginSystem
	case OriginUser:
		return store.MessageOriginUser
	default:
		return store.MessageOriginUntrusted
	}
}
