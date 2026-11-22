//go:build !vulnerable

package agent

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/mcp"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// The hardened build's marketplace channel (M4a T5). Nothing here dials
// a publisher: the pinned manifests are read from the install rows the
// platform recorded at consent, and every description enters the context
// as its OWN span, origin `publisher`, marked and wrapped -- never
// concatenated into the platform's system text (SR-B6-2, m4a D5). The
// marking is for the record and for detection; the consent leg is the
// control (SR-B4-3's rule, unchanged since M2).
//
// The pin is what the org approved, so the description the model sees
// is byte-identical to what install review showed (SR-B9-13's
// one-rendering rule applied to listings) -- and byte-identical to what
// the vulnerable build concatenates pre-flip, which is D1a: the model
// emits the same Action in both modes, and a hardened pass can only
// come from the gate.

// CatalogPrompt returns "" in this build, DELIBERATELY: concatenating
// publisher bytes into the platform's system text is the vulnerable
// build's planted shape, and this build will not ship it.
func CatalogPrompt(_ context.Context, _ *pgxpool.Pool, _ string) (string, error) {
	return "", nil
}

// CatalogSpans renders the org's installed tools from their PINNED
// manifests: one span per tool description, verbatim, origin
// `publisher`, Role system (the channel that emitted the span is the
// platform's catalog; the ORIGIN carries the trust class -- that is the
// whole point of keeping the two axes distinct, span.go's own rule).
//
// An unparsable pin is skipped with a note, not fatal: the install rows
// are validated at write, so this is corruption handling, and a corrupt
// pin must not silence the session's other tools (SR-B6-7's mercy,
// mirrored from the vulnerable build for parity of everything EXCEPT
// the thing under test).
func CatalogSpans(ctx context.Context, pool *pgxpool.Pool, orgID string) ([]Span, error) {
	installs, err := store.ForOrg(pool, orgID).Installs(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent: listing installs in org %s: %w", orgID, err)
	}
	var out []Span
	for _, ins := range installs {
		tools, err := mcp.Parse([]byte(ins.PinnedManifest))
		if err != nil {
			out = append(out, Span{
				Origin: OriginPublisher,
				Role:   RoleSystem,
				Text:   fmt.Sprintf("[installed tool %s: its pinned manifest is unreadable: %v]", ins.EndpointURL, err),
			})
			continue
		}
		for _, t := range tools {
			out = append(out, Span{
				Origin: OriginPublisher,
				Role:   RoleSystem,
				Text:   fmt.Sprintf("Installed tool %s: %s", t.Name, t.Description),
			})
		}
	}
	return out, nil
}
