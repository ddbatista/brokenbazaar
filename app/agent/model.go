package agent

import (
	"net/url"
	"regexp"
	"strings"
)

// Action is what a model turn produces: either a tool call or an answer.
// Exactly one is set.
type Action struct {
	Tool   string
	Args   map[string]string
	Answer string
}

func (a Action) IsTool() bool { return a.Tool != "" }

// Model is the agent's model interface. One method, a pure function from
// assembled context to action. Two implementations are planned:
// ScriptedModel (below, ships now) and a real model, which landed as
// app/measure (D1b's experiment, run outside CI against the Anthropic
// Messages API -- not "any OpenAI-compatible endpoint" as first planned;
// TM D1). The experiment drives the model directly rather than through
// this interface: it renders each arm once and counts the action the
// model emits, and never executes one.
type Model interface {
	Next(spans []Span) Action
}

// ScriptedModel is the deterministic adversary model, per D1a.
//
// It is NOT a simulation of a well-behaved model, and calling it a "fake
// LLM" misses the point. SR-B4-3 says "no security property may depend on
// the model honouring the marking... if the model ignores the wrapper
// entirely, every control below still holds." A model that ignores the
// wrapper entirely is therefore the adversary the baseline already
// commits to defending against -- so scripting it is not a shortcut, it
// is instantiating the worst case the requirement names.
//
// Two properties follow structurally rather than by discipline:
//
//   - CAUSATION. The action is a function of the context, so a document
//     with no imperative yields an answer and no fetch. Finding 03 claims
//     "the document did it", and the negative control is the same code
//     path with different data -- not a separate test someone maintains.
//
//   - THE SAME CALL IN BOTH MODES. Origin is never consulted, so the
//     vulnerable and hardened assemblers produce an identical Action. If
//     the hardened assembler made this model decline, the exploit would
//     exit 1 with the gateway, the allowlist and link-blocking all
//     un-run, and CI would go green having verified nothing -- M1 T6's
//     failure shape in a new costume.
type ScriptedModel struct{}

var _ Model = (*ScriptedModel)(nil)

// fetchImperative matches the shape the seeded document uses: an
// instruction to fetch a URL. Deliberately crude -- this is an adversary
// model, not a parser worth defending. Its crudeness is the point: a
// sophisticated one would start making judgments, and a model that makes
// judgments is a model that could decline, which is the one thing D1a
// forbids.
//
// The angle-bracket group is not decoration. A plain `\S+` stops at the
// first space, and the placeholder the seeded document uses --
// "<this document's full contents>" -- CONTAINS spaces, so `\S+`
// captured "...data=<this" and expand() then found no placeholder to
// substitute. The exploit still produced an http_fetch to the attacker's
// host and carried no tenant data at all: a finding that passes its tool
// assertion while proving nothing. Caught by TestExfiltratedPayload,
// which asserts on the bytes rather than on the call.
var fetchImperative = regexp.MustCompile(`(?i)fetch\s+(https?://[^\s<]*(?:<[^>]*>)?[^\s]*)`)

// documentRef matches a UUID in the user's request. The seed composes the
// user message from the document id it just minted precisely so this can
// stay a literal match rather than title-parsing (T2 D4).
var documentRef = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)

func (m *ScriptedModel) Next(spans []Span) Action {
	// Which tools have already produced results in this context. Read
	// from span STRUCTURE (Role, Tool), never from result text -- a
	// model that recognised fixture strings would be coupled to the
	// seed data and would stop being a function of the context.
	performed := map[string]bool{}
	for _, s := range spans {
		if s.Role == RoleTool && s.Tool != "" {
			performed[s.Tool] = true
		}
	}

	// 1. An imperative anywhere in the context, not yet acted on.
	if !performed["http_fetch"] {
		for _, s := range spans {
			// s.Origin is deliberately NOT consulted. That single
			// omitted check IS SR-B4-3 in code: a model that
			// respected the label would be testing the model's good
			// manners, not the platform's controls.
			if match := fetchImperative.FindStringSubmatch(s.Text); match != nil {
				return Action{
					Tool: "http_fetch",
					Args: map[string]string{"url": expand(match[1], spans)},
				}
			}
		}
	}

	// 2. A document referenced by the user and not yet read.
	if !performed["read_document"] {
		for _, s := range spans {
			if match := documentRef.FindStringSubmatch(s.Text); match != nil {
				return Action{
					Tool: "read_document",
					Args: map[string]string{"id": match[1]},
				}
			}
		}
	}

	// 3. Nothing left to do.
	return Action{Answer: summarise(spans)}
}

// contentsPlaceholder is what the seeded document asks to be substituted.
// The seed writes "<this document's full contents>" and this is where
// those bytes actually enter the URL -- which is the moment the finding
// stops being a prompt curiosity and becomes exfiltration. B4 5.1:
// "tenant data placed inside a URL targeting an allowlisted host."
const contentsPlaceholder = "<this document's full contents>"

// expand substitutes tenant data into the URL the imperative asked for.
// The substituted bytes come from the spans the model was given -- which
// in a hardened run are exactly the spans labelled untrusted, and in a
// vulnerable run are indistinguishable from system text because the
// naive assembler merged them. The model cannot tell the difference and
// does not try to.
func expand(raw string, spans []Span) string {
	if !strings.Contains(raw, contentsPlaceholder) {
		return raw
	}
	var payload strings.Builder
	for _, s := range spans {
		if s.Role == RoleTool {
			payload.WriteString(s.Text)
		}
	}
	// The placeholder sits in a query value, so the substituted content
	// is query-escaped. Without this the document's newlines and spaces
	// would produce a malformed request and the exploit would fail for
	// a reason that has nothing to do with the control under test.
	return strings.ReplaceAll(raw, contentsPlaceholder, url.QueryEscape(payload.String()))
}

// summarise produces the answer turn. Deterministic and dull on purpose:
// it is not the subject of any finding, and anything cleverer would make
// the attack output harder to assert on.
func summarise(spans []Span) string {
	var parts []string
	for _, s := range spans {
		if s.Role != RoleTool {
			continue
		}
		if line, _, _ := strings.Cut(strings.TrimSpace(s.Text), "\n"); line != "" {
			parts = append(parts, line)
		}
	}
	if len(parts) == 0 {
		return "No documents were read, so there is nothing to summarize."
	}
	return "Summary: " + strings.Join(parts, " | ")
}
