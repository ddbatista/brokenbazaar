// M4b T4: the skill channel's shared half -- the deterministic trigger
// matcher, the load record, and the loop's span vocabulary. The two
// builds' halves live in skills_vulnerable.go / skills_hardened.go,
// exactly as the catalog channel split (marketplace_*.go): the
// vulnerable build's poison sites are the concatenated system prompt
// and the unverified load; the hardened build's spans carry the
// publisher origin, and its loader is T5's mediation.
package agent

import (
	"strings"
)

// SkillLoad is one load event's record: what fired, what entered the
// context, and -- the honest half -- whether the platform verified
// the bytes before loading them. Verified=false in a record is not an
// error state; it is the naive build's advisory pin saying its own
// quiet part out loud, the same way install rows hold pins the
// vulnerable executor never reads (finding 08's shape, extended to
// the load path by M4b's leaf 1.2).
type SkillLoad struct {
	SkillName string
	InstallID string
	Trigger   string // the trigger that matched
	Digest    string // the install row's pinned digest -- recorded, not consulted, in the naive build
	BodySHA   string // sha256 of the bytes actually loaded, always computed and always recorded
	Verified  bool   // whether those two agreed at load time
}

// matchTrigger is the platform's deterministic S7: after the trigger's
// GRAMMAR words are dropped (the fixed stop-list below -- "use when
// the user asks to read a document" is a condition about reading
// documents, and its grammar is not the condition), every remaining
// content token must appear in the user's message. It is a floor, not
// a semantics judgement -- baseline branch 2's note holds (a malicious
// trigger is indistinguishable from a correct one by inspection), so
// the matcher only decides PRESENCE, and the two builds differ on what
// presence buys: the naive build loads every match (the persuasion
// contest has no resolution rule, so it never resolves), the hardened
// build loads exactly one, by precedence (SR-B9-4, T5).
//
// Tokens are lowercased alphanumerics of length >= 3, so "a", "to",
// "of" and punctuation never carry a match. The stop-list is the
// documented vocabulary of trigger grammar; anything not on it is
// content, and content is what must appear.
var triggerStopList = map[string]bool{
	"use": true, "uses": true, "using": true,
	"when": true, "whenever": true, "while": true,
	"the": true, "this": true, "that": true, "these": true, "those": true,
	"and": true, "for": true, "with": true, "into": true,
	"asks": true, "ask": true, "asked": true, "requesting": true, "wants": true, "needs": true,
	"user": true, "users": true, "their": true, "them": true, "your": true, "you": true,
	"prepare": true, "handling": true, "about": true,
	"are": true, "was": true, "has": true, "have": true,
}

func matchTrigger(trigger, message string) bool {
	triggerTokens := contentTokens(trigger)
	if len(triggerTokens) == 0 {
		return false
	}
	msgTokens := make(map[string]bool)
	for _, tok := range tokenize(message) {
		msgTokens[tok] = true
	}
	for _, tok := range triggerTokens {
		if !msgTokens[tok] {
			return false
		}
	}
	return true
}

// contentTokens is the trigger's tokens minus the stop-list: the words
// that must actually appear for the trigger to claim its situation.
func contentTokens(trigger string) []string {
	var out []string
	for _, tok := range tokenize(trigger) {
		if !triggerStopList[tok] {
			out = append(out, tok)
		}
	}
	return out
}

func tokenize(s string) []string {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !('a' <= r && r <= 'z' || '0' <= r && r <= '9')
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) >= 3 {
			out = append(out, f)
		}
	}
	return out
}

// skillIndexLine renders one index entry for the model's context.
// Both builds render the SAME line for the same entry (D1a's rule
// applied to the new channel: the text is identical pre-flip, so the
// model's Action is too, and any hardened divergence can only come
// from the gate). What differs between the builds is WHERE the line
// enters: the naive build concatenates it into the platform's system
// text wearing the platform's voice; the hardened build pins it as an
// origin-publisher span, marked and wrapped.
func skillIndexLine(name, description string, triggers []string) string {
	return "Skill " + name + " (fires when: " + strings.Join(triggers, "; ") + "): " + description
}
