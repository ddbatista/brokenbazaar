package agent

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// Result is what a tool returns. Text is the full result (it becomes a
// transcript row and a context span); Summary is the short note recorded
// on the tool_calls row, where the full bytes deliberately do not go --
// tenant data is stored once, in messages, where the context comes from.
type Result struct {
	Tool    string
	Text    string
	Summary string
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
	Execute(ctx context.Context, a Action) (Result, error)
}

// Loop is the agent loop: assemble, ask the model, dispatch, repeat.
//
// Residual, declared rather than discovered later: Loop holds a
// *store.SessionStore, and the store package exports ForOrg -- so code
// in this package COULD read documents directly, bypassing D5b's
// service-secret mediation entirely. No such code path exists, and
// prompt influence cannot create one: an attacker who controls the
// document body has no way to make the loop call ForOrg. The exposure is
// therefore compromise-level, the same severity as M2-N1's shared bridge
// network, and it is code discipline rather than structure that keeps it
// closed. The session plane is the only thing this loop legitimately
// needs; the document plane reaching it is the raw-pool rot finding from
// M1's T9 audit arriving for real.
type Loop struct {
	Assembler    Assembler
	Model        Model
	Executor     ToolExecutor
	Sessions     *store.SessionStore
	SystemPrompt string
	MaxTurns     int
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

		res, err := l.Executor.Execute(ctx, action)
		if err != nil {
			// T3 ships no executor implementation; both tagged
			// stubs refuse here, so the run stops with the intended
			// call named. Honestly incomplete beats fake-complete:
			// a stub returning canned results would let T3's tests
			// pass against data that does not exist.
			return out, fmt.Errorf("agent: executing %s: %w", action.Tool, err)
		}

		// SR-B4-7: tool output is untrusted by default, including
		// first-party tools. There is no short-string exemption and no
		// "it came from our own database" exemption -- that second one
		// is finding 03's entire premise.
		if _, err := l.Sessions.AppendMessage(ctx, store.Message{
			Role:   store.MessageRoleTool,
			Origin: store.MessageOriginUntrusted,
			Body:   res.Text,
		}); err != nil {
			return out, fmt.Errorf("agent: recording %s result: %w", action.Tool, err)
		}
		spans = append(spans, Span{
			Origin: OriginUntrusted,
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
