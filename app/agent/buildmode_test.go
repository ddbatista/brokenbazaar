package agent

import (
	"strings"
	"testing"
)

// T6 D2: the agent image's binary is chosen by a build arg, and a build
// arg can be forgotten. The binary therefore checks itself against the
// environment it was started in, and refuses on disagreement -- so a
// stale image or an unset AGENT_TAGS is a loud startup failure, never a
// vulnerable binary quietly running in a stack that believes it is
// hardened. Runs under both tag sets (`make test`), so each binary is
// tested against both environments.

func TestBuildModeAgreesWithItsOwnMode(t *testing.T) {
	if err := CheckBuildMatchesEnv(Mode() == "hardened"); err != nil {
		t.Fatalf("a %s binary refused a %s environment: %v", Mode(), Mode(), err)
	}
}

func TestBuildModeRefusesTheOtherMode(t *testing.T) {
	err := CheckBuildMatchesEnv(Mode() != "hardened")
	if err == nil {
		t.Fatalf("a %s binary accepted the opposite environment", Mode())
	}
	if !strings.Contains(err.Error(), "AGENT_TAGS") {
		t.Errorf("error %q should tell the operator which knob to turn", err)
	}
}
