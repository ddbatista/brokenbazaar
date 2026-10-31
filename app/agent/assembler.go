package agent

import (
	"fmt"
	"strings"

	"github.com/ddbatista/brokenbazaar/app/store"
)

// Assembler turns a session's transcript into the context the model sees.
// This is the component the house rule applies to in M2 -- not the model.
// The labelled implementation below is written FIRST; the naive one is a
// documented departure from it, per AGENTS.md: "write the correct
// implementation before the vulnerable one."
type Assembler interface {
	Assemble(systemPrompt string, msgs []store.Message) []Span
}

// originOf maps a stored ingestion label onto a span label. The two
// vocabularies are identical by construction (T3 D1), so this is a
// total, lossless mapping and not a judgment call. An unknown value
// falls to untrusted rather than system: an unrecognised label is a
// reason to trust content less, never more (SR-B4-4's "no operation
// upgrades class", applied to the mapping itself).
func originOf(o store.MessageOrigin) Origin {
	switch o {
	case store.MessageOriginSystem:
		return OriginSystem
	case store.MessageOriginUser:
		return OriginUser
	default:
		return OriginUntrusted
	}
}

func roleOf(r store.MessageRole) Role {
	switch r {
	case store.MessageRoleSystem:
		return RoleSystem
	case store.MessageRoleUser:
		return RoleUser
	case store.MessageRoleAssistant:
		return RoleAssistant
	default:
		return RoleTool
	}
}

// LabelledAssembler is the hardened assembler: one span per transcript
// row, labels carried from the store's ingestion record, nothing merged.
//
// SR-B4-1 is satisfied because the label is a struct field and the
// content is Text -- the label is not IN the content, so content cannot
// alter it. SR-B4-2 is satisfied because spans are never concatenated:
// a future RemoteModel maps one span to one API message, so the boundary
// survives as JSON structure rather than as a sentinel someone has to
// trust.
//
// Note what this assembler does NOT do: it does not tell the model
// anything about trust. D1a -- "the label was never for the model, it is
// for the gate." Nothing here asks the model to respect a marking, which
// is exactly why SR-B4-3 holds: no security property depends on the
// model honouring it, because the model is never asked to.
type LabelledAssembler struct{}

var _ Assembler = (*LabelledAssembler)(nil)

func (a *LabelledAssembler) Assemble(systemPrompt string, msgs []store.Message) []Span {
	spans := make([]Span, 0, len(msgs)+1)
	spans = append(spans, Span{Origin: OriginSystem, Role: RoleSystem, Text: systemPrompt})
	for _, m := range msgs {
		spans = append(spans, Span{
			Origin: originOf(m.Origin),
			Role:   roleOf(m.Role),
			Text:   m.Body,
		})
	}
	return spans
}

// NaiveAssembler is the planted bug: leaf B4 2.1, "untrusted content
// concatenated into the same string as system instructions with no
// separation at all." The committed threat model names the mechanism --
// "one fmt.Sprintf that joins system text and document bodies" -- and
// that is literally what this is.
//
// It returns ONE span. That is the bug made visible in the type system:
// diff this against LabelledAssembler and three spans become one. The
// span is labelled system, which is a lie -- but it is the lie the
// concatenation forces, because once the strings are joined there is no
// per-byte origin left to report. The wrong label is a CONSEQUENCE of
// the bug, not a second bug.
//
// Both assemblers feed the same ScriptedModel, which is required: D1a
// needs an identical Action in both modes so that a hardened pass can
// only come from the gate refusing, never from the model behaving
// differently. ScriptedModel reads Text and never Origin, so merging the
// spans changes what the model SEES while leaving what it DOES
// unchanged.
//
// Audit provenance does NOT come from here (T3 D3). The agent's audit
// record sources provenance from the store's ingestion labels, which
// both modes write identically, so SR-B4-14 ("every ingestion logged
// with origin and class", ship in both modes) stays true where it is
// actually claimed -- at ingestion. This bug is scoped precisely to what
// the model sees, which is what B4 2.1 describes.
type NaiveAssembler struct{}

var _ Assembler = (*NaiveAssembler)(nil)

func (a *NaiveAssembler) Assemble(systemPrompt string, msgs []store.Message) []Span {
	var b strings.Builder
	b.WriteString(systemPrompt)
	for _, m := range msgs {
		// The whole finding, in one call: system text and a document
		// body joined with nothing between them but whitespace.
		fmt.Fprintf(&b, "\n\n%s", m.Body)
	}
	return []Span{{Origin: OriginSystem, Role: RoleSystem, Text: b.String()}}
}
