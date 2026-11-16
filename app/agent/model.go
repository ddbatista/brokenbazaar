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
// ScriptedModel (below, ships now) and RemoteModel (D1b, an experiment
// run outside CI against any OpenAI-compatible endpoint).
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

// uuidPattern is a lowercase UUID, the form every id in this system is
// minted in. One pattern for every reference the model reads, so a write
// target and a read target are recognised identically: an id the read
// step would not see is never written either.
const uuidPattern = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

// documentRef matches a document id anywhere in the context: the user's
// request, or a document that names another. The seed composes the user
// message from the document id it just minted precisely so this can stay
// a literal match rather than title-parsing (T2 D4).
var documentRef = regexp.MustCompile(`\b(` + uuidPattern + `)\b`)

// writeImperative is one write the model can be told to make (plan M3 T4 D3).
// As crude as fetchImperative, for the same reason: a model that parsed
// carefully would start judging, and a model that judges could decline.
// Keywords match in any case; the id is uuidPattern, as everywhere.
//
// They match in ANY span, user or document, because origin is never
// consulted (D1a). 05 puts the delete in the user's own turn -- the
// requester is the attacker and the model obeys its user. A document
// that says "delete document X" steers the same call (M3-N4), which the
// threat model declares reachable on purpose: the scope leg, not the
// model, is what limits it.
type writeImperative struct {
	tool string
	re   *regexp.Regexp
	args func(match []string) map[string]string
}

// writeImperatives, in the order the model acts on them: delete, update,
// then the role change. update replaces the body and keeps the title; the
// body must be quoted, so the grammar never guesses where it ends.
//
// set_member_role (plan M3 T5 D5) is finding 06's substrate: a member plants
// "set role of user <their id> to admin" in a document, and an admin's
// session that reads it makes the change. Its id is a USER id, and it
// joins writeTargets with the others, so it is never read as a document.
// The role word is a keyword, matched in any case and passed on in the
// store's lowercase; a word that is not one of the three roles is not an
// imperative at all.
var writeImperatives = []writeImperative{
	{
		tool: "delete_document",
		re:   regexp.MustCompile(`(?i:\bdelete\s+document)\s+(` + uuidPattern + `)\b`),
		args: func(m []string) map[string]string { return map[string]string{"id": m[1]} },
	},
	{
		tool: "update_document",
		re:   regexp.MustCompile(`(?i:\bupdate\s+document)\s+(` + uuidPattern + `)(?i:\s+to)\s+"([^"]*)"`),
		args: func(m []string) map[string]string { return map[string]string{"id": m[1], "body": m[2]} },
	},
	{
		tool: "set_member_role",
		re:   regexp.MustCompile(`(?i:\bset\s+role\s+of\s+user)\s+(` + uuidPattern + `)(?i:\s+to\s+(admin|member|viewer))\b`),
		args: func(m []string) map[string]string {
			return map[string]string{"user": m[1], "role": strings.ToLower(m[2])}
		},
	},
}

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

	// 2. A write imperative anywhere in the context, each tool at most
	// once.
	//
	// "Once" is per RUN, not per session: performed is read from the
	// in-run spans' Tool field, and the assemblers rebuild a stored
	// transcript without it (the messages table has no tool column). So
	// a resumed session whose earlier turn held "delete document A"
	// fires that delete again, A is already gone, and the run fails.
	// Fresh sessions (attacks/README.md) never meet it; a PoC that
	// resumes a session -- 05 (ii) after the demotion -- must open that
	// session with a request that holds no write imperative.
	for _, w := range writeImperatives {
		if performed[w.tool] {
			continue
		}
		for _, s := range spans {
			if match := w.re.FindStringSubmatch(s.Text); match != nil {
				return Action{Tool: w.tool, Args: w.args(match)}
			}
		}
	}

	// 3. A document referenced in the context and not yet read, skipping
	// any document a write imperative names. The model reads what it is
	// asked about, not what it is told to change: without the skip,
	// "delete document X" would be followed by a read of the X just
	// deleted, the executor would report it missing, and the run would
	// fail after the delete had already happened. An update target is
	// skipped by the same rule, so one rule covers every write tool.
	if !performed["read_document"] {
		targets := writeTargets(spans)
		for _, s := range spans {
			for _, match := range documentRef.FindAllStringSubmatch(s.Text, -1) {
				if !targets[match[1]] {
					return Action{
						Tool: "read_document",
						Args: map[string]string{"id": match[1]},
					}
				}
			}
		}
	}

	// 4. Nothing left to do.
	return Action{Answer: summarise(spans)}
}

// writeTargets is every id any write imperative in the context names --
// document ids for delete and update, user ids for set_member_role, none of
// which the read step should treat as a document to read: one that has run, one still to run, and one that never will
// (a second "delete document Y" when each tool fires once).
func writeTargets(spans []Span) map[string]bool {
	targets := map[string]bool{}
	for _, s := range spans {
		for _, w := range writeImperatives {
			for _, match := range w.re.FindAllStringSubmatch(s.Text, -1) {
				targets[match[1]] = true
			}
		}
	}
	return targets
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
