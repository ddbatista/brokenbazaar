package main

import (
	"strings"
	"testing"
)

// T7 D1: the agent runs either an EXISTING session (-session) or opens a
// FRESH one for a user's request (-acting-for + -message). Exactly one
// shape, chosen explicitly -- a flag combination that could mean either
// is refused rather than guessed, because "which session did this run
// write to" is the first thing an exploit or an investigator needs to
// know.

func TestTargetRunsAnExistingSession(t *testing.T) {
	got, err := parseTarget("o1", "s1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.fresh() || got.sessionID != "s1" || got.orgID != "o1" {
		t.Errorf("got %+v", got)
	}
}

func TestTargetOpensAFreshSession(t *testing.T) {
	got, err := parseTarget("o1", "", "u1", "  Please summarise document d1  ")
	if err != nil {
		t.Fatal(err)
	}
	if !got.fresh() || got.actingFor != "u1" {
		t.Errorf("got %+v", got)
	}
	// Stored as the user typed it, minus surrounding whitespace.
	if got.message != "Please summarise document d1" {
		t.Errorf("message = %q", got.message)
	}
}

func TestTargetRefusesAmbiguousOrIncompleteFlags(t *testing.T) {
	cases := []struct {
		name                             string
		org, session, actingFor, message string
		mention                          string
	}{
		{"no org", "", "s1", "", "", "-org"},
		{"neither shape", "o1", "", "", "", "-session"},
		{"both shapes", "o1", "s1", "u1", "hi", "not both"},
		{"message without acting-for", "o1", "", "", "hi", "-acting-for"},
		{"acting-for without message", "o1", "", "u1", "", "-message"},
		{"blank message", "o1", "", "u1", "   ", "-message"},
		// -acting-for with -session would silently be ignored (the
		// session row already says who it acts for) -- refuse instead.
		{"acting-for with session", "o1", "s1", "u1", "", "not both"},
	}
	for _, c := range cases {
		_, err := parseTarget(c.org, c.session, c.actingFor, c.message)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.mention) {
			t.Errorf("%s: error %q should mention %q", c.name, err, c.mention)
		}
	}
}
