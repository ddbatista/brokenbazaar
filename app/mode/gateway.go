package mode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// GatewayURLEnv names the gateway's base URL. Both the API and the agent
// read it to ask the gateway which mode it is in, once, at startup.
const GatewayURLEnv = "GATEWAY_URL"

// CheckGateway is M2-N4's control: a process refuses to start unless the
// gateway reports the same mode the process parsed. The API calls it
// before serving; the agent calls it before its first turn, because the
// agent is a one-shot `compose run` that can be pointed at a stack
// started in the other mode.
//
// Why at startup, and why refuse: a split-brain stack -- hardened API,
// vulnerable gateway, or the reverse -- is a runtime state no request
// reveals and precisely the one an attacker would choose. Converting it
// into a startup failure is the controls-that-fire-before-a-request-
// exists pattern (defenses/), applied to configuration.
//
// Runs in BOTH modes (T6 D3): agreement is configuration integrity, not
// a planted control. A vulnerable API with a hardened gateway is not a
// finding anyone asked for; it is an operator mistake, and it fails the
// same way.
//
// Only a positive, well-formed answer counts as agreement. An
// unreachable gateway, a non-200, a body without a boolean `hardened`,
// or `status` other than "ok" is an ABSENT answer, and an absent answer
// refuses -- the same rule T5 learned from Rego, where an undefined
// operand silently removed a check. Absent answers are retried up to
// `attempts` times (the gateway may still be booting); a definite
// mismatch is not retried, because asking again cannot change it.
func CheckGateway(ctx context.Context, client *http.Client, gatewayURL string, want bool, attempts int, wait time.Duration) error {
	if gatewayURL == "" {
		return fmt.Errorf("%s is not set: cannot confirm the gateway agrees this stack is %s (M2-N4)",
			GatewayURLEnv, Name(want))
	}
	url := strings.TrimRight(gatewayURL, "/") + "/healthz"

	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("gateway mode check: %w (last: %v)", ctx.Err(), last)
			case <-time.After(wait):
			}
		}
		got, err := askGatewayMode(ctx, client, url)
		if err != nil {
			last = err
			continue
		}
		if got != want {
			return fmt.Errorf("mode split brain: this process is %s, gateway at %s reports %s -- refusing to start (M2-N4)",
				Name(want), gatewayURL, Name(got))
		}
		return nil
	}
	return fmt.Errorf("gateway at %s gave no usable mode after %d attempts: %v -- refusing to start rather than assume agreement (M2-N4)",
		gatewayURL, attempts, last)
}

// askGatewayMode performs one probe. Any error means "no answer", never
// "agreement".
func askGatewayMode(ctx context.Context, client *http.Client, url string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false, err
	}
	// *bool, so a missing or null field is distinguishable from false.
	// The T5 gateway answered {"mode":"true"} -- a string under another
	// key -- and that body must not satisfy this check.
	var body struct {
		Status   string `json:"status"`
		Hardened *bool  `json:"hardened"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return false, fmt.Errorf("healthz body is not the expected JSON: %v", err)
	}
	if body.Status != "ok" {
		return false, fmt.Errorf("healthz status is %q, not \"ok\"", body.Status)
	}
	if body.Hardened == nil {
		return false, errors.New(`healthz has no boolean "hardened" field`)
	}
	return *body.Hardened, nil
}

// Startup probe budgets. The API waits longer than the agent: Compose
// starts it right behind the gateway, while the agent is a one-shot run
// against a stack that should already be up.
const (
	APIProbeAttempts   = 15
	AgentProbeAttempts = 5
	probeTimeout       = 2 * time.Second
	probeWait          = time.Second
)

// CheckGatewayFromEnv is CheckGateway as both binaries call it at
// startup: GATEWAY_URL from the environment, a bounded per-attempt
// timeout, and an overall deadline that cannot outlive the attempts.
func CheckGatewayFromEnv(ctx context.Context, want bool, attempts int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(attempts)*(probeTimeout+probeWait))
	defer cancel()
	return CheckGateway(ctx, &http.Client{Timeout: probeTimeout},
		os.Getenv(GatewayURLEnv), want, attempts, probeWait)
}
