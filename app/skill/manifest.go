// Package skill owns the SKILL.md bundle contract, the way package mcp
// owns the manifest contract (m4a D1: one parser, normative, both
// languages agree byte for byte because pinning is over raw bytes).
//
// The bundle is YAML-ish frontmatter above a --- line and a body below:
//
//	---
//	name: meeting-notes
//	description: "Prepare meeting notes from a document."
//	triggers:
//	  - "use when the user asks to prepare meeting notes"
//	capabilities:
//	  - read_document
//	  - update_document
//	references:
//	  - https://docs.example/formatting.md
//	---
//	Body text. These are instructions the agent is designed to obey.
//
// The parse is STRICT, and every rejection below is SR-B9-13 or the
// publish-validation half of SR-B9-7 in code: the description the model
// will read at S6 is the same string the admin read at S3, so anything
// that could make two readers see one string differently is refused at
// the door rather than normalised silently.
package skill

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Index is the parse of a bundle's frontmatter: what the install stores
// beside the pin (migration 005, skill_index) and what S3's review, S6's
// index answer and S8's loader all render from. One parse, one home
// (SR-B9-13's single rendering, by construction).
type Index struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Triggers     []string `json:"triggers"`
	Capabilities []string `json:"capabilities"`
	References   []string `json:"references"`
	Body         string   `json:"body"`
}

// ExampleBundle is the canonical well-formed bundle: one home for the
// bytes the parser's test pins a digest over and the seed publishes as
// the platform's own meeting-notes skill (SR-B9-11 -- the platform
// publisher goes through the same parse, the same pin and the same
// index as anyone else; first-party is a precedence value, never an
// exemption). Its sha256 is
// e1f06dcd6f369f47eea7738a1a3113cc0de7f2293087c63fbba16696d0e34c79 --
// pinned in TestDigestVector so the Python fixture family can be held
// to the same bytes later, exactly as mcp's manifest vector was.
const ExampleBundle = `---
name: meeting-notes
description: "Prepare meeting notes from a document the user names."
triggers:
  - "use when the user asks to prepare meeting notes"
capabilities:
  - read_document
  - update_document
---
Read the document the user names, then update the same document with a short section titled Notes: at the end. Do not create new documents.
`

// ParseFrontmatter validates and parses a SKILL.md bundle. It is the
// syntax authority for type='skill' listings: the store calls it at
// publish and at install, and nothing else re-derives the index, ever.
//
// Rejections, each a stated rule rather than a parse accident:
//   - the bundle must open with a --- line and close the frontmatter
//     with a second one; no preamble, no trailing spaces on fences;
//   - exactly the five keys are known; an unknown key is refused (a
//     silent ignore would be a field the model never sees and the
//     reviewer never knew was dropped);
//   - name is [a-z0-9_-]{1,64};
//   - triggers is required and non-empty (a skill that cannot say when
//     it fires never loads, and a listing that cannot fire is a lie);
//   - capabilities is required and every entry must be a platform tool
//     the session vocabulary knows (the CALLER supplies that vocabulary's
//     one home -- authz.ActionFor -- because importing it here would
//     cycle store -> skill -> authz -> store; a copied list inside this
//     package is the two-homes drift this repo argues against);
//   - references is optional, and every entry must be an absolute
//     http(s) URL -- undeclared fetch surfaces do not exist in this
//     vocabulary by construction (SR-B9-9's declared half);
//   - description is required and passes the single-rendering rules:
//     printable-only (no bidi or format runes, which the model and a
//     human can read in opposite orders), no combining marks (submit
//     composed forms -- a normaliser here would be a second opinion
//     about what the string is, and the pin is over exact bytes), and
//     no mixed scripts (a Latin string carrying Cyrillic or Greek
//     lookalikes is the homoglyph floor -- script identity is not
//     semantics a reader can be trusted to catch);
//   - the body is required and non-empty: the body is the artifact
//     (SR-B9-1's whole point), and a bundle without one cannot be the
//     artifact anyone approved.
func ParseFrontmatter(bundle []byte, knownTool func(string) bool) (Index, error) {
	text := string(bundle)
	if !strings.HasPrefix(text, "---\n") {
		return Index{}, fmt.Errorf("skill: bundle must open with a --- line")
	}
	rest := text[len("---\n"):]
	closeIdx := strings.Index(rest, "\n---\n")
	if closeIdx < 0 {
		return Index{}, fmt.Errorf("skill: frontmatter is never closed by a --- line")
	}
	head := rest[:closeIdx]
	body := rest[closeIdx+len("\n---\n"):]

	idx := Index{}
	seen := map[string]bool{}
	var list *[]string
	for ln, line := range strings.Split(head, "\n") {
		n := ln + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if list == nil {
				return Index{}, fmt.Errorf("skill: frontmatter line %d: list item outside a list", n)
			}
			item, err := unquote(strings.TrimSpace(trimmed[2:]))
			if err != nil {
				return Index{}, fmt.Errorf("skill: frontmatter line %d: %w", n, err)
			}
			if item == "" {
				return Index{}, fmt.Errorf("skill: frontmatter line %d: empty list item", n)
			}
			*list = append(*list, item)
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			return Index{}, fmt.Errorf("skill: frontmatter line %d: not a key: value line", n)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if seen[key] && key != "" {
			return Index{}, fmt.Errorf("skill: frontmatter line %d: key %q repeated", n, key)
		}
		seen[key] = true
		var err error
		switch key {
		case "name":
			idx.Name, err = unquote(val)
			if err != nil {
				return Index{}, fmt.Errorf("skill: frontmatter line %d: %w", n, err)
			}
		case "description":
			idx.Description, err = unquote(val)
			if err != nil {
				return Index{}, fmt.Errorf("skill: frontmatter line %d: %w", n, err)
			}
		case "triggers":
			idx.Triggers = []string{}
			list = &idx.Triggers
		case "capabilities":
			idx.Capabilities = []string{}
			list = &idx.Capabilities
		case "references":
			idx.References = []string{}
			list = &idx.References
		default:
			return Index{}, fmt.Errorf("skill: frontmatter line %d: unknown key %q (strict parse: nothing is ignored)", n, key)
		}
	}

	if idx.Name == "" {
		return Index{}, fmt.Errorf("skill: name is required")
	}
	if len(idx.Name) > 64 {
		return Index{}, fmt.Errorf("skill: name longer than 64 bytes")
	}
	for _, r := range idx.Name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return Index{}, fmt.Errorf("skill: name %q: only [a-z0-9_-] is allowed", idx.Name)
		}
	}
	if idx.Description == "" {
		return Index{}, fmt.Errorf("skill: description is required")
	}
	if err := singleRendering(idx.Description); err != nil {
		return Index{}, fmt.Errorf("skill: description: %w", err)
	}
	if len(idx.Triggers) == 0 {
		return Index{}, fmt.Errorf("skill: at least one trigger is required (a skill that cannot fire never loads)")
	}
	for _, t := range idx.Triggers {
		if err := singleRendering(t); err != nil {
			return Index{}, fmt.Errorf("skill: trigger %q: %w", t, err)
		}
	}
	if len(idx.Capabilities) == 0 {
		return Index{}, fmt.Errorf("skill: capabilities is required (the ceiling needs the declaration; an empty declaration buys strictly nothing, which is the honest minimum)")
	}
	for _, c := range idx.Capabilities {
		if !knownTool(c) {
			return Index{}, fmt.Errorf("skill: capability %q is not a platform tool the session vocabulary knows", c)
		}
	}
	for _, ref := range idx.References {
		u, err := url.Parse(ref)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return Index{}, fmt.Errorf("skill: reference %q is not an absolute http(s) URL", ref)
		}
	}
	if strings.TrimSpace(body) == "" {
		return Index{}, fmt.Errorf("skill: the body is required and non-empty -- the body is the artifact (SR-B9-1)")
	}
	idx.Body = body
	return idx, nil
}

// singleRendering enforces SR-B9-13's rules on a string both a human and
// the model will read: printable-only, composed-only, one script
// family. It is a floor, not a semantics judgement -- m4b §4's N1
// records the honest limit: the wrap bounds syntax, never what a string
// can be chosen to mean.
func singleRendering(s string) error {
	hasLatin, hasCyrillic, hasGreek := false, false, false
	for _, r := range s {
		if r == '\n' || r == '\t' {
			return fmt.Errorf("control newline/tab inside a single-line field")
		}
		if !unicode.IsPrint(r) {
			return fmt.Errorf("non-printing rune U+%04X", r)
		}
		if unicode.Is(unicode.Mn, r) {
			return fmt.Errorf("combining mark U+%04X: submit composed (NFC) forms; the pin is over exact bytes and no normaliser runs here", r)
		}
		switch {
		case unicode.Is(unicode.Latin, r):
			hasLatin = true
		case unicode.Is(unicode.Cyrillic, r):
			hasCyrillic = true
		case unicode.Is(unicode.Greek, r):
			hasGreek = true
		}
	}
	if hasLatin && (hasCyrillic || hasGreek) {
		return fmt.Errorf("mixed scripts: Latin with Cyrillic/Greek is the homoglyph floor")
	}
	return nil
}

// unquote strips one layer of surrounding double quotes from a scalar.
// A quote character INSIDE a quoted scalar is refused rather than
// guessed (strict parse, same rule as unknown keys): there is no escape
// vocabulary, because two parsers disagreeing about escapes is how the
// S3 string and the S6 string stop being one string.
func unquote(v string) (string, error) {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		inner := v[1 : len(v)-1]
		if strings.Contains(inner, `"`) {
			return "", fmt.Errorf("quote inside a quoted scalar (no escape vocabulary: submit a bare scalar or reword)")
		}
		return inner, nil
	}
	return v, nil
}
