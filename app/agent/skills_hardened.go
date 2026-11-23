//go:build !vulnerable

package agent

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// The hardened build's skill channel (M4b T4). The index renders as
// origin-publisher spans -- wrapped and marked, never concatenated
// into the platform's speech (SR-B9-14, CatalogSpans's own pattern,
// applied to the per-user index). The marking is for the record and
// for detection; the legs are the control, exactly as every marking
// in this repo has been since M2.
//
// The LOADER is T5's mediation and does not exist yet: re-hash before
// every load (SR-B9-1, the M4a drift mechanism reused), the disclosure
// (SR-B9-5), the load events (SR-B9-6), and the authority-route facts
// the ceiling will need (SR-B9-2). Until T5 lands it, this build
// loads nothing -- and the exploits that need a hardened load (09's
// body variant, 10's beats) run after T5, per the task order.

// SkillsPrompt returns "" in this build, DELIBERATELY: concatenating
// publisher bytes into the platform's system text is the vulnerable
// build's planted shape, and this build will not ship it.
func SkillsPrompt(_ context.Context, _ *pgxpool.Pool, _, _ string) (string, error) {
	return "", nil
}

// SkillSpans renders the member's authorised index from the install
// rows' stored parse: one span per skill, the SAME line the naive
// build concatenates (D1a -- identical text, identical Action, so any
// hardened divergence can only come from the gate), origin
// `publisher`, Role system.
//
// An entry whose stored parse is missing is skipped with a note, not
// fatal (SR-B6-7's mercy, mirrored for parity of everything except
// the thing under test).
func SkillSpans(ctx context.Context, pool *pgxpool.Pool, orgID, userID string) ([]Span, error) {
	index, err := store.ForOrg(pool, orgID).SkillIndexForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("agent: reading the skill index for %s: %w", userID, err)
	}
	var out []Span
	for _, e := range index {
		if len(e.Triggers) == 0 {
			out = append(out, Span{
				Origin: OriginPublisher,
				Role:   RoleSystem,
				Text:   fmt.Sprintf("[skill %s: its stored index is unreadable]", e.Name),
			})
			continue
		}
		out = append(out, Span{
			Origin: OriginPublisher,
			Role:   RoleSystem,
			Text:   skillIndexLine(e.Name, e.Description, e.Triggers),
		})
	}
	return out, nil
}

// LoadSkills is T5's mediation, not T4's: the hardened loader (the
// re-hash before every load, the disclosure, the load events, the
// ceiling's authority facts) lands with the gate work. Until then
// this build loads nothing, and the ordering is deliberate -- an
// exploit that asserts a hardened load would be asserting a stub.
func LoadSkills(_ context.Context, _ *pgxpool.Pool, _, _, _ string) ([]Span, []SkillLoad, error) {
	return nil, nil, nil
}
