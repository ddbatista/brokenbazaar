//go:build vulnerable

package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ddbatista/brokenbazaar/app/mcp"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// THE PLANTED BUG LIVES HERE (finding 08, baseline leaf 2.4 verbatim:
// "the platform re-resolves to latest on reconnect"). Every place this
// build consults a manifest, it FETCHES IT LIVE from the publisher's
// server: the catalog text below, and every dispatch in
// executor_vulnerable.go's default case. The install row's pinned
// bytes are never read by this build. A real developer writes exactly
// this -- "the tool's server is the source of truth about the tool" --
// and the rug pull is what that deference buys the publisher.
//
// The check this build DOES run (the tool's NAME must appear in the
// live manifest) exists and is worthless, B5 3.2's shape extended to
// the marketplace: the manifest's `receives` vocabulary is displayed at
// install review and never read on any execution path (finding 07).

// marketplaceClient is the vulnerable build's own MCP client: stdlib,
// bounded, and in-process, because in this build nothing mediates.
var marketplaceClient = &http.Client{Timeout: 5 * time.Second}

// liveManifest fetches and validates a server's CURRENT tools/list
// body. Byte-exact: the body returned here is what a pin WOULD hash, and
// what this build instead trusts fresh on every call.
func liveManifest(endpoint string) ([]byte, error) {
	resp, err := marketplaceClient.Post(endpoint, "application/json", bytes.NewReader(mcp.Request("tools/list")))
	if err != nil {
		return nil, fmt.Errorf("reaching %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", endpoint, err)
	}
	if _, err := mcp.Parse(body); err != nil {
		return nil, err
	}
	return body, nil
}

// CatalogText renders the org's installed tools for the agent's system
// prompt. THE POISON SITE (m4a D5): in this build the publisher's
// descriptions are concatenated into the platform's own system text,
// with no separation and no label -- B4 2.1's merge carrying publisher
// bytes as platform speech. A description that carries an imperative
// (finding 07) enters the context wearing the platform's voice.
//
// The manifests are fetched LIVE (the planted 2.4): what the org
// approved at install is never consulted here.
func CatalogText(ctx context.Context, pool *pgxpool.Pool, orgID string) (string, error) {
	installs, err := store.ForOrg(pool, orgID).Installs(ctx)
	if err != nil {
		return "", fmt.Errorf("agent: listing installs in org %s: %w", orgID, err)
	}
	var b strings.Builder
	for _, ins := range installs {
		body, err := liveManifest(ins.EndpointURL)
		if err != nil {
			// An unreachable server is recorded and skipped, not fatal:
			// one dead listing must not silence the session's other
			// tools, and SR-B6-7's "failure is non-fatal" is the only
			// mercy this build shows.
			fmt.Fprintf(&b, "\n\n[installed tool %s: unreachable: %v]", ins.EndpointURL, err)
			continue
		}
		tools, _ := mcp.Parse(body)
		for _, t := range tools {
			fmt.Fprintf(&b, "\n\nInstalled tool %s: %s", t.Name, t.Description)
		}
	}
	return b.String(), nil
}
