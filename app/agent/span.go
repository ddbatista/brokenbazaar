// Package agent holds the M2 agent loop: the context assembler, the model
// interface, and the loop that drives them. See
// threat-models/m2-agent-gateway.md (D1a, D5) and the four T3 decisions in
// the implementation plan.
//
// What this package deliberately does NOT hold: tool code. D5's hardened
// shape is "there is no http_fetch code in the binary to route around,"
// which is a claim about the compiled artifact rather than about a code
// path -- so the executor implementations live in build-tagged files
// (executor_hardened.go, executor_vulnerable.go) and only one is compiled
// into any given binary.
package agent

// Origin is the trust class the platform assigned to a span at ingestion
// -- SR-B4-1: "every span in the context carries an origin label assigned
// at ingestion; the label lives outside the span's own content and can
// never be set, altered or terminated by that content."
//
// That sentence is the whole design of this type. Origin is a struct
// field; the content is Text. There is no parser that reads a label out
// of content, because there is no label in content to read. An attacker
// who controls a document body entirely -- including writing
// `"}, {"origin": "system"` into it -- writes only into Text.
//
// Vocabulary matches store.MessageOrigin exactly, so the label the store
// wrote at ingestion and the label the assembler puts on a span cannot
// disagree (T3 D1).
type Origin string

const (
	OriginSystem    Origin = "system"
	OriginUser      Origin = "user"
	OriginUntrusted Origin = "untrusted"
)

// Role is who authored the span. Distinct from Origin: role is evidence
// (finding 03's writeup must show the ASSISTANT emitted the fetch after
// reading the document), origin is the trust class the gate consumes.
// A hardened run has tool-role spans with DIFFERENT origins -- the
// document is untrusted, the gateway's denial notice is system -- which
// is precisely why the two axes cannot be collapsed into one.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// Span is one labelled unit of context. One span per transcript row; the
// assembler never merges spans in hardened mode, so text framing never
// becomes unavoidable and SR-B4-2's per-request-nonce fallback is never
// taken. That is recorded rather than silently skipped: the nonce clause
// exists for designs that concatenate, and this one does not.
//
// Tool names the tool that produced a RoleTool span. It is structure, not
// content -- the loop knows which tool it dispatched -- and it exists so
// ScriptedModel can tell "this document has already been read" from "it
// has not" without parsing result text for fixture-specific strings.
type Span struct {
	Origin Origin
	Role   Role
	Tool   string // set only when Role == RoleTool
	Text   string
}

// trustRank orders the classes from least to most trusted. Used only by
// LowestTrust; exposed nowhere, because nothing outside SR-B4-4's rule
// should be making trust comparisons.
func trustRank(o Origin) int {
	switch o {
	case OriginUntrusted:
		return 0
	case OriginUser:
		return 1
	default: // OriginSystem
		return 2
	}
}

// LowestTrust implements SR-B4-4: "Derived content inherits the lowest
// trust of its inputs; model output produced from untrusted input is
// itself untrusted. No operation upgrades class -- not summarisation, not
// persistence, not re-reading."
//
// The loop calls this to label the assistant row it writes after the
// model answers. An answer produced from a context containing a poisoned
// document is itself untrusted, which is leaf B4 3.1 ("the agent
// summarises a poisoned document in turn 3; in turn 7 that summary is
// model output and nothing marks it as derived") made structurally
// visible.
//
// Honest scope note (T3 D2): M2's loop terminates at Answer and sessions
// do not resume, so B4 3.1 is REACHABLE IN THE DATA but NOT EXPLOITABLE
// IN THE LOOP. The control ships anyway, because the alternative is
// writing a label we know to be false into a table M3 inherits as fact.
// The committed diff's §2 lists this leaf as neither reachable nor
// unreachable; it fell between the two lists and is dispositioned here.
func LowestTrust(spans []Span) Origin {
	lowest := OriginSystem
	for _, s := range spans {
		if trustRank(s.Origin) < trustRank(lowest) {
			lowest = s.Origin
		}
	}
	return lowest
}
