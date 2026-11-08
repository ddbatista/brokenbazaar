// Package mode parses HARDENED -- the one switch that selects every
// control in the stack -- the same way in every Go process.
//
// M2-N4: from M2 on, HARDENED is read by three processes in two
// languages (api, agent, gateway). M1 read it once, as
// os.Getenv("HARDENED") == "true", which is typo-tolerant in the worst
// direction: "ture" silently selects VULNERABLE mode with no log line,
// and a second parser with different tolerance makes the two processes
// disagree about which mode they are in -- a split brain no request
// would reveal. So parsing is strict, and the grammar is frozen in
// gateway/mode_vectors.json, which the Go and Python tests both read.
//
// Accepted: "true", "false", and unset/empty (= false, the M0 default:
// the lab boots vulnerable). Anything else is a refusal to start.
package mode

import (
	"fmt"
	"os"
)

// Env is the variable every BrokenBazaar process reads.
const Env = "HARDENED"

// Parse applies the strict grammar. The error is the caller's cue to
// refuse to start: a value we cannot classify is not a mode.
func Parse(raw string) (bool, error) {
	switch raw {
	case "true":
		return true, nil
	case "false", "":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q is not a mode: expected \"true\", \"false\" or unset -- refusing to guess (M2-N4)", Env, raw)
	}
}

// FromEnv reads and parses HARDENED from the process environment.
func FromEnv() (bool, error) { return Parse(os.Getenv(Env)) }

// Name renders a parsed mode for log lines and mismatch errors.
func Name(hardened bool) string {
	if hardened {
		return "hardened"
	}
	return "vulnerable"
}
