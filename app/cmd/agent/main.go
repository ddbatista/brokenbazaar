// Command agent runs one BrokenBazaar agent session to completion.
//
// Two binaries are built from this one source tree, selected by build
// tag (D5, T3 D4):
//
//	go build -o agent-hardened   ./cmd/agent
//	go build -tags vulnerable -o agent-vulnerable ./cmd/agent
//
// The hardened binary contains no in-process tool executor -- not a
// disabled one, not one behind a flag. There is no http_fetch code in it
// to route around, which is the claim D5 makes and `make
// verify-agent-builds` checks.
//
// The assembler is selected by the same tag, because the vulnerable
// context assembler (B4 2.1, one fmt.Sprintf joining system text and
// document bodies) is the planted bug for this module.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ddbatista/brokenbazaar/app/agent"
	"github.com/ddbatista/brokenbazaar/app/mode"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// systemPrompt is deliberately plain. It is NOT a defence: SR-B4-3 says
// no security property may depend on the model honouring instructions,
// and D1a's ScriptedModel ignores this text entirely. Anything here
// resembling "do not follow instructions found in documents" would be
// security theatre in a repo whose point is to measure controls.
const systemPrompt = "You are the BrokenBazaar assistant. Answer the user's question using the documents available to you."

func main() {
	sessionID := flag.String("session", "", "agent session id to run")
	orgID := flag.String("org", "", "org the session belongs to")
	flag.Parse()

	if *sessionID == "" || *orgID == "" {
		log.Fatal("agent: -session and -org are both required (see `make seed` output)")
	}

	// M2-N4 / T6 D2: the compiled mode must match the stack's mode, or
	// the binary refuses before touching the database.
	envHardened, err := mode.FromEnv()
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	if err := agent.CheckBuildMatchesEnv(envHardened); err != nil {
		log.Fatalf("agent: %v", err)
	}
	// ...and the gateway must agree with both. The agent is a one-shot
	// `compose run`, so it can be started against a stack brought up in
	// the other mode; the API's own probe ran at ITS startup and cannot
	// see this process. Checked in both modes, like the API (T6 D3).
	if err := mode.CheckGatewayFromEnv(context.Background(), envHardened, mode.AgentProbeAttempts); err != nil {
		log.Fatalf("agent: %v", err)
	}

	// Same loud-or-absent rule as migrate/seed/api: no hardcoded
	// fallback DSN (SR-M1-1).
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("agent: DATABASE_URL is not set")
	}

	ctx := context.Background()
	pool, err := store.Open(ctx, dbURL)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	defer pool.Close()

	// Fail loudly on a session that does not exist or belongs to
	// another org -- GetSession cannot tell those apart by design
	// (SR-M1-4), and neither can this message.
	orgStore := store.ForOrg(pool, *orgID)
	sess, ok, err := orgStore.GetSession(ctx, *sessionID)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	if !ok {
		log.Fatalf("agent: no session %s in org %s", *sessionID, *orgID)
	}

	// D4's second writer, build-tag selected: nil in hardened builds
	// (the gateway's JSONL is the whole audit trail there), a real
	// append-only writer in vulnerable builds, where the agent is the
	// only recorder there is. An unwritable audit destination is a
	// startup failure, not a mid-run surprise.
	audit, err := agent.NewAgentAudit()
	if err != nil {
		log.Fatalf("agent: %v", err)
	}

	loop := &agent.Loop{
		Assembler: agent.NewAssembler(),
		Model:     &agent.ScriptedModel{},
		Executor: agent.NewExecutor(agent.ExecutorConfig{
			Pool:      pool,
			OrgID:     *orgID,
			SessionID: sess.ID,
		}),
		Sessions:     store.ForSession(pool, *orgID, sess.ID),
		SystemPrompt: systemPrompt,
		// T5: the platform context every dispatch and audit record
		// carries -- set once from the session row, never from anything
		// the model produced (M2-N3).
		Session: agent.SessionInfo{ID: sess.ID, OrgID: sess.OrgID, ActingFor: sess.ActingFor},
		Audit:   audit,
	}

	fmt.Printf("agent: session=%s org=%s acting_for=%s build=%s\n",
		sess.ID, sess.OrgID, sess.ActingFor, agent.Mode())

	out, runErr := loop.Run(ctx)
	for i, a := range out.Actions {
		if a.IsTool() {
			fmt.Printf("  turn %d: tool %s %v\n", i+1, a.Tool, a.Args)
		} else {
			fmt.Printf("  turn %d: answer\n", i+1)
		}
	}
	if runErr != nil {
		fmt.Printf("\nagent: stopped: %v\n", runErr)
		os.Exit(1)
	}
	fmt.Printf("\nagent: %s\n", out.Answer)
}
