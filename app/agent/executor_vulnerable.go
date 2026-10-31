//go:build vulnerable

package agent

import (
	"context"
	"fmt"
)

// NaiveExecutor is the planted bug's home: leaf B5 2.1, "a built-in or
// first-party tool bypasses the gateway because it is 'internal'." It
// dispatches in-process and the gateway is never consulted.
//
// This file is compiled into the vulnerable binary ONLY. That is the
// whole of D5: mediation is enforced by what code exists where, not by
// a check that remembers to run. There is no build of this program in
// which both this type and the hardened path are reachable.
//
// T4 fills in the tools:
//   - http_fetch: http.Get on Args["url"] with no allowlist, following
//     redirects without re-evaluating them (B5 4.3), and re-resolving
//     at dial time so the evaluated target and the executed target can
//     differ (SR-B5-3's violation, which looks correct while being
//     wrong).
//   - read_document: an in-process store read, which is exactly the
//     unmediated path D5b's service secret exists to prevent in
//     hardened mode.
type NaiveExecutor struct{}

var _ ToolExecutor = (*NaiveExecutor)(nil)

// NewExecutor is the build-tag selected constructor. Both files define
// it; only one is compiled.
func NewExecutor() ToolExecutor { return &NaiveExecutor{} }

// NewAssembler returns the naive concatenating assembler -- the planted
// B4 2.1 bug. Selected by the same build tag as the executor: the two
// halves of the mode are chosen once, at compile time, together.
func NewAssembler() Assembler { return &NaiveAssembler{} }

// Mode names the build for startup logging. See the hardened file.
func Mode() string { return "vulnerable" }

func (e *NaiveExecutor) Execute(_ context.Context, a Action) (Result, error) {
	return Result{}, fmt.Errorf(
		"naive in-process executor not wired until T4 (would dispatch without consulting the gateway): tool=%s args=%v",
		a.Tool, a.Args)
}
