//go:build !vulnerable

package agent

import (
	"context"
	"fmt"
	"os"
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
// T5/T6 fill in the POST /gate call. T3 ships the seam and refuses
// loudly: a stub returning canned results would let the loop appear to
// work against data no tool produced.
type GatewayExecutor struct {
	gatewayURL string
}

var _ ToolExecutor = (*GatewayExecutor)(nil)

// NewExecutor is the build-tag selected constructor. Both files define
// it; only one is compiled.
func NewExecutor() ToolExecutor {
	return &GatewayExecutor{gatewayURL: os.Getenv("GATEWAY_URL")}
}

// NewAssembler returns the labelled, provenance-preserving assembler.
// Selected by the same build tag as the executor, so a binary cannot
// end up with a hardened executor and a naive assembler -- the two
// halves of the mode are chosen once, at compile time, together.
func NewAssembler() Assembler { return &LabelledAssembler{} }

// Mode names the build for startup logging. M2-N4 is the split-brain
// problem -- two processes reading HARDENED in two languages with
// nothing making them agree -- and a build that announces which binary
// it is at least makes the disagreement visible in the logs. The
// mode-agreement check itself lands in T6.
func Mode() string { return "hardened" }

func (e *GatewayExecutor) Execute(_ context.Context, a Action) (Result, error) {
	return Result{}, fmt.Errorf(
		"gateway executor not wired until T5 (would POST %s to %q): tool=%s args=%v",
		"/gate", e.gatewayURL, a.Tool, a.Args)
}
