//go:build vulnerable

package main

import (
	"github.com/ddbatista/brokenbazaar/app/skill"
	"github.com/ddbatista/brokenbazaar/app/store"
)

// The VULNERABLE build's skill review payload: the spec's own S3,
// verbatim -- "an org admin browses the catalog and installs it," and
// what the catalog shows is a name and a description. No body, no
// declared capabilities, no references: the org reviews exactly what
// the listing's copy says, and the bytes that will execute at S8 are
// an implementation detail the platform never surfaces.
//
// This is finding 09's planted bug, and it is spec-faithful ON
// PURPOSE (m4b-skills.md's third derivation): a real developer writes
// exactly this, because the naive mental model is that the description
// is the artifact -- the catalog shows the description, so the
// description is what the org is consenting to. The hardened build
// (review_hardened.go) redefines the review surface per SR-B9-1: the
// full body, the declared caps, and the digest an install will pin.
//
// The parse still runs here, because the description shown must be the
// BUNDLE'S OWN description (the same string the index will render at
// S6) -- single rendering holds even in the naive build, or the review
// and the index would disagree about what the org saw.
type skillReviewPayload struct {
	Type         string                  `json:"type"`
	Name         string                  `json:"name"`
	Description  string                  `json:"description"`
	Publisher    store.Publisher         `json:"publisher"`
	Version      int                     `json:"version"`
	InstallCount int                     `json:"install_count"`
	MutationLog  []store.CatalogMutation `json:"mutation_log"`
}

func buildSkillReviewPayload(idx skill.Index, detail store.CatalogItemDetail) any {
	return skillReviewPayload{
		Type:         "skill",
		Name:         idx.Name,
		Description:  idx.Description,
		Publisher:    detail.Publisher,
		Version:      detail.Version,
		InstallCount: detail.InstallCount,
		MutationLog:  detail.MutationLog,
	}
}
