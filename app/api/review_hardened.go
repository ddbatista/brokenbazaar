//go:build !vulnerable

package main

import (
	"github.com/ddbatista/brokenbazaar/app/skill"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// The HARDENED build's skill review payload: SR-B9-1's redefined
// review surface. "The artifact presented for approval is the artifact
// that executes" -- the admin sees the FULL SKILL.md body, the
// declared capabilities (what the ceiling will hold the session to,
// SR-B9-2), the declared triggers and references, and the exact
// digest an install will pin, so the approval is answerable against
// the bytes that load at S8. The description is the same string the
// index renders at S6 (one parse, one home, SR-B9-13).
//
// The naive build (review_vulnerable.go) is the spec's own S3 and is
// finding 09's planted bug; this file is the honest product.
type skillReviewPayload struct {
	Type          string                  `json:"type"`
	Name          string                  `json:"name"`
	Description   string                  `json:"description"`
	Triggers      []string                `json:"triggers"`
	Capabilities  []string                `json:"capabilities"`
	References    []string                `json:"references"`
	Body          string                  `json:"body"`
	PinningDigest string                  `json:"pinning_digest"`
	Publisher     store.Publisher         `json:"publisher"`
	Version       int                     `json:"version"`
	InstallCount  int                     `json:"install_count"`
	MutationLog   []store.CatalogMutation `json:"mutation_log"`
}

func buildSkillReviewPayload(idx skill.Index, detail store.CatalogItemDetail) any {
	return skillReviewPayload{
		Type:          "skill",
		Name:          idx.Name,
		Description:   idx.Description,
		Triggers:      idx.Triggers,
		Capabilities:  idx.Capabilities,
		References:    idx.References,
		Body:          idx.Body,
		PinningDigest: detail.ManifestDigest,
		Publisher:     detail.Publisher,
		Version:       detail.Version,
		InstallCount:  detail.InstallCount,
		MutationLog:   detail.MutationLog,
	}
}
