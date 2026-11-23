//go:build vulnerable

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// THE PLANTED BUGS LIVE HERE (M4b, findings 09 and 10's channels --
// every gap this module measures, in the agent path, as the M4a house
// rule requires: a route that misbehaved would blur the gap; the
// review-surface split at the API is the one deliberate exception,
// skills.go's header in api/).
//
// Three sites, each a real developer's mental model:
//
// 1. SkillsPrompt concatenates the member's skill index into the
//    platform's own system text, unmarked -- the description is
//    resident every turn, so being installed is delivery (baseline
//    leaf 5.1, finding 09's description-only variant). The naive
//    mental model: the description is a label, and labels are copy.
//
// 2. LoadSkills loads EVERY skill whose trigger matched -- there is no
//    resolution rule, because in this build selection is the model's
//    problem (the persuasion contest, SR-B9-4's negative space).
//
// 3. The load never re-hashes: the install row's digest is recorded
//    and ignored, exactly as the vulnerable executor ignored the
//    pinned manifest (08's advisory pin, one surface up). The body
//    loads from the stored parse wearing the platform's voice --
//    instruction by entry, never by verification (SR-B9-7's gap).

// SkillsPrompt renders the member's authorised skills for the agent's
// system prompt. THE POISON SITE (09's description channel): index
// lines concatenated raw, publisher bytes as platform speech.
func SkillsPrompt(ctx context.Context, pool *pgxpool.Pool, orgID, userID string) (string, error) {
	index, err := store.ForOrg(pool, orgID).SkillIndexForUser(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("agent: reading the skill index for %s: %w", userID, err)
	}
	var b strings.Builder
	for _, e := range index {
		fmt.Fprintf(&b, "\n\n%s", skillIndexLine(e.Name, e.Description, e.Triggers))
	}
	return b.String(), nil
}

// SkillSpans returns nil in this build, deliberately: the vulnerable
// build's index channel is the concatenated prompt above, and a
// second channel would blur which site the finding measures
// (CatalogSpans's own rule, restated).
func SkillSpans(_ context.Context, _ *pgxpool.Pool, _, _ string) ([]Span, error) {
	return nil, nil
}

// LoadSkills matches the run's user message against the index's
// triggers and loads EVERY match's body, unverified, from the stored
// parse. The returned spans wear the system origin: the body is
// instruction the agent is meant to obey, and in this build nothing
// ever checked that the bytes deserve the class.
//
// The load records are the caller's to write to the audit: BodySHA is
// always computed (the honest record), Verified is always false (the
// naive build's quiet part, said out loud), and 09's second beat
// asserts the ABSENCE of a record where the description channel fired
// without a single load -- delivery by residency, provable against
// this record's emptiness.
func LoadSkills(ctx context.Context, pool *pgxpool.Pool, orgID, userID, message string) ([]Span, []SkillLoad, error) {
	if strings.TrimSpace(message) == "" {
		return nil, nil, nil
	}
	org := store.ForOrg(pool, orgID)
	index, err := org.SkillIndexForUser(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: reading the skill index for %s: %w", userID, err)
	}
	var spans []Span
	var loads []SkillLoad
	for _, e := range index {
		matched := ""
		for _, trig := range e.Triggers {
			if matchTrigger(trig, message) {
				matched = trig
				break
			}
		}
		if matched == "" {
			continue
		}
		ins, ok, err := org.Install(ctx, e.InstallID)
		if err != nil || !ok {
			// An install that vanished mid-run is skipped, not fatal:
			// the index is a rendering and the row is the truth, and
			// one dead row must not silence the session (SR-B6-7's
			// mercy, restated for the load path).
			continue
		}
		if ins.SkillIndex == nil {
			continue
		}
		body := ins.SkillIndex.Body
		sum := sha256.Sum256([]byte(body))
		spans = append(spans, Span{
			Origin: OriginSystem, // the bug: instruction by entry, unverified
			Role:   RoleSystem,
			Text:   "Skill " + e.Name + " loaded. Its instructions:\n" + body,
		})
		loads = append(loads, SkillLoad{
			SkillName: e.Name,
			InstallID: e.InstallID,
			Trigger:   matched,
			Digest:    ins.PinnedDigest, // recorded, never compared
			BodySHA:   hex.EncodeToString(sum[:]),
			Verified:  false, // the advisory pin, stated
		})
	}
	return spans, loads, nil
}
