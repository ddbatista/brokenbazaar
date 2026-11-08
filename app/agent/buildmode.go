package agent

import (
	"fmt"

	"github.com/ddbatista/brokenbazaar/app/mode"
)

// CheckBuildMatchesEnv is the agent's half of M2-N4's mode agreement.
//
// The API probes the gateway; the agent cannot be probed (it is a
// one-shot `docker compose run`, not a service), so it checks itself:
// the mode compiled into this binary (build tag, T3 D4) against the
// mode the stack was started in ($HARDENED, parsed strictly). They are
// two independent facts -- the binary is fixed at image build time, the
// environment at container start -- and nothing else ties them
// together.
func CheckBuildMatchesEnv(envHardened bool) error {
	built := Mode() == "hardened"
	if built == envHardened {
		return nil
	}
	return fmt.Errorf("this agent binary was built %s but %s says the stack is %s -- "+
		"rebuild the agent image with the matching AGENT_TAGS (make up / make harden set it) (M2-N4, T6 D2)",
		Mode(), mode.Env, mode.Name(envHardened))
}
