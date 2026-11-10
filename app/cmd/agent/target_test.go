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
	got, err := parseTarget("o1", "s1", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.fresh() || got.sessionID != "s1" || got.orgID != "o1" {
		t.Errorf("got %+v", got)
	}
}

func TestTargetOpensAFreshSession(t *testing.T) {
	got, err := parseTarget("o1", "", "u1", "  Please summarise document d1  ", "read_document")
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
		name                                    string
		org, session, actingFor, message, scope string
		mention                                 string
	}{
		{"no org", "", "s1", "", "", "", "-org"},
		{"neither shape", "o1", "", "", "", "", "-session"},
		{"both shapes", "o1", "s1", "u1", "hi", "read_document", "not both"},
		{"message without acting-for", "o1", "", "", "hi", "read_document", "-acting-for"},
		{"acting-for without message", "o1", "", "u1", "", "read_document", "-message"},
		{"blank message", "o1", "", "u1", "   ", "read_document", "-message"},
		// -acting-for with -session would silently be ignored (the
		// session row already says who it acts for) -- refuse instead.
		{"acting-for with session", "o1", "s1", "u1", "", "", "not both"},
		// Plan M3 T2 D4: a fresh session states its scope (SR-B3-5, explicitly
		// requested). There is no default to fall back on.
		{"fresh session without scope", "o1", "", "u1", "hi", "", "-scope"},
		{"blank scope", "o1", "", "u1", "hi", "  ", "-scope"},
		{"empty scope entry", "o1", "", "u1", "hi", "read_document,,http_fetch", "empty"},
		{"duplicate scope entry", "o1", "", "u1", "hi", "read_document, read_document", "twice"},
		// -scope with -session would silently be ignored: an existing
		// session's scope is on its row and has no update path (SR-B3-6).
		{"scope with session", "o1", "s1", "", "", "read_document", "-scope"},
	}
	for _, c := range cases {
		_, err := parseTarget(c.org, c.session, c.actingFor, c.message, c.scope)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.mention) {
			t.Errorf("%s: error %q should mention %q", c.name, err, c.mention)
		}
	}
}

// Plan M3 T2 D4: the scope is the comma-separated tool list, trimmed, in the
// order given. It is consent, not authority (m3-delegation.md M3-N5):
// nothing here checks the tools against the user's role.
func TestTargetParsesTheScope(t *testing.T) {
	got, err := parseTarget("o1", "", "u1", "hi", " read_document , http_fetch ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"read_document", "http_fetch"}
	if strings.Join(got.scope, "|") != strings.Join(want, "|") {
		t.Errorf("scope = %q, want %q", got.scope, want)
	}
}
