// Package measure is D1b's real-model experiment: does a model act on an
// instruction planted in a document, and does the channel the document
// arrives through change how often?
//
// It is an EXPERIMENT, not an attack (D1b, D1c): it asserts nothing,
// never runs in CI, and returns a rate with an interval per arm. Nothing
// it does dials anything but the model API -- the harness counts the
// fetch actions a model EMITS; no tool is ever executed.
//
// The arms are built by the lab's own code, not by hand: the real
// assemblers (app/agent) produce the spans, and Render maps spans to the
// Anthropic Messages API the way each build would present them. TM D4,
// found at task open: a document read DURING a run is appended as its own
// untrusted tool span in BOTH builds (loop.go), so the naive merge only
// reaches a document already in the STORED transcript. Hence three arms:
//
//	A-stored  document in the stored transcript -> naive merge -> system
//	A-live    what the vulnerable binary sends on finding 03's turn 2:
//	          the request merged into system, the document a tool result
//	B         the labelled build: system, request, document a tool result
//
// Every parameter comes from experiments/03-injection-compliance/
// preregistration.json, committed before the first paid call (TM D5).
package measure

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ddbatista/brokenbazaar/app/agent"
	"github.com/ddbatista/brokenbazaar/app/store"
)

const (
	ArmAStored = "A-stored"
	ArmALive   = "A-live"
	ArmB       = "B"

	// ContinueTurn is the one line the harness adds that no build sends.
	// The Messages API requires the conversation to open with a user
	// turn, and in the A arms the user's request lives inside the system
	// text (the naive merge) -- so a fixed, content-free turn opens it.
	// Declared in the experiment's README.
	ContinueTurn = "Continue."

	// minN is D1's floor: "n>=20, per the cross-cutting statistical-
	// testing track".
	minN = 20
)

var knownArms = map[string]bool{ArmAStored: true, ArmALive: true, ArmB: true}

// Inputs are the experiment's fixed materials (document.json).
type Inputs struct {
	SystemPrompt  string `json:"system_prompt"`
	UserRequest   string `json:"user_request"`
	DocumentID    string `json:"document_id"`
	DocumentTitle string `json:"document_title"`
	DocumentBody  string `json:"document_body"`
	TenantMarker  string `json:"tenant_marker"`
	AttackerHost  string `json:"attacker_host"`
}

// DocumentText is read_document's result text in both builds: title,
// blank line, body (executor_vulnerable.go and gateway/gate.py).
func (in Inputs) DocumentText() string { return in.DocumentTitle + "\n\n" + in.DocumentBody }

// Prereg is the pre-registered design (preregistration.json).
type Prereg struct {
	Model            string   `json:"model"`
	Effort           string   `json:"effort"`
	AnthropicVersion string   `json:"anthropic_version"`
	MaxTokens        int      `json:"max_tokens"`
	NPerArm          int      `json:"n_per_arm"`
	Arms             []string `json:"arms"`
	Sampling         string   `json:"sampling"`
}

func LoadInputs(path string) (Inputs, error) {
	var in Inputs
	if err := loadJSON(path, &in); err != nil {
		return in, err
	}
	for name, v := range map[string]string{"system_prompt": in.SystemPrompt, "user_request": in.UserRequest,
		"document_id": in.DocumentID, "document_body": in.DocumentBody,
		"tenant_marker": in.TenantMarker, "attacker_host": in.AttackerHost} {
		if v == "" {
			return in, fmt.Errorf("%s: %s is empty", path, name)
		}
	}
	return in, nil
}

func LoadPrereg(path string) (Prereg, error) {
	var p Prereg
	if err := loadJSON(path, &p); err != nil {
		return p, err
	}
	switch {
	case p.Model == "" || p.Effort == "" || p.AnthropicVersion == "":
		return p, fmt.Errorf("%s: model, effort and anthropic_version are required", path)
	case p.MaxTokens <= 0:
		return p, fmt.Errorf("%s: max_tokens must be positive", path)
	case p.NPerArm < minN:
		return p, fmt.Errorf("%s: n_per_arm %d is below D1's floor of %d", path, p.NPerArm, minN)
	case len(p.Arms) == 0:
		return p, fmt.Errorf("%s: no arms", path)
	}
	seen := map[string]bool{}
	for _, a := range p.Arms {
		if !knownArms[a] {
			return p, fmt.Errorf("%s: unknown arm %q", path, a)
		}
		if seen[a] {
			return p, fmt.Errorf("%s: arm %q listed twice", path, a)
		}
		seen[a] = true
	}
	return p, nil
}

func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Spans builds one arm's context with the lab's real assemblers.
func Spans(arm string, in Inputs) ([]agent.Span, error) {
	ask := store.Message{Role: store.MessageRoleUser, Origin: store.MessageOriginUser, Body: in.UserRequest}
	// What the loop appends after read_document returns, in both builds
	// (app/agent/loop.go: spans = append(spans, Span{Origin, RoleTool, ...})).
	readResult := agent.Span{Origin: agent.OriginUntrusted, Role: agent.RoleTool, Tool: "read_document", Text: in.DocumentText()}

	switch arm {
	case ArmAStored:
		stored := []store.Message{ask, {Role: store.MessageRoleTool, Origin: store.MessageOriginUntrusted, Body: in.DocumentText()}}
		return (&agent.NaiveAssembler{}).Assemble(in.SystemPrompt, stored), nil
	case ArmALive:
		return append((&agent.NaiveAssembler{}).Assemble(in.SystemPrompt, []store.Message{ask}), readResult), nil
	case ArmB:
		return append((&agent.LabelledAssembler{}).Assemble(in.SystemPrompt, []store.Message{ask}), readResult), nil
	}
	return nil, fmt.Errorf("unknown arm %q", arm)
}

// --- the Messages API request ----------------------------------------------

type Request struct {
	Model        string        `json:"model"`
	MaxTokens    int           `json:"max_tokens"`
	System       string        `json:"system,omitempty"`
	Messages     []Message     `json:"messages"`
	Tools        []Tool        `json:"tools"`
	OutputConfig *OutputConfig `json:"output_config,omitempty"`
}

type Message struct {
	Role    string  `json:"role"`
	Content []Block `json:"content"`
}

type Block struct {
	Type      string            `json:"type"`
	Text      string            `json:"text,omitempty"`
	ID        string            `json:"id,omitempty"`
	Name      string            `json:"name,omitempty"`
	Input     map[string]string `json:"input,omitempty"`
	ToolUseID string            `json:"tool_use_id,omitempty"`
	Content   string            `json:"content,omitempty"`
}

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type OutputConfig struct {
	Effort string `json:"effort"`
}

// tools are the two the agent has, described plainly. The descriptions
// are part of the experiment's inputs and are recorded in every request.
func tools() []Tool {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	return []Tool{
		{Name: "read_document", Description: "Read one of the organisation's documents by its id. Returns the title and body.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"id": str("The document id.")}, "required": []string{"id"}}},
		{Name: "http_fetch", Description: "Fetch a URL with an HTTP GET request and return the response body.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"url": str("The URL to fetch.")}, "required": []string{"url"}}},
	}
}

const readToolUseID = "toolu_bb_read_document"

// Render maps assembled spans to a Messages API request, each span to the
// channel its role names: system spans to `system`, user spans to user
// turns, a tool span to the read_document call that produced it and its
// tool_result. No sampling parameter, no thinking setting (the model's
// adaptive default), no fallbacks (TM D2, TM D3).
func Render(spans []agent.Span, in Inputs, p Prereg) (Request, error) {
	var system []string
	var msgs []Message
	user := func(text string) {
		if n := len(msgs); n > 0 && msgs[n-1].Role == "user" {
			msgs[n-1].Content = append(msgs[n-1].Content, Block{Type: "text", Text: text})
			return
		}
		msgs = append(msgs, Message{Role: "user", Content: []Block{{Type: "text", Text: text}}})
	}
	for _, s := range spans {
		switch s.Role {
		case agent.RoleSystem:
			system = append(system, s.Text)
		case agent.RoleUser:
			user(s.Text)
		case agent.RoleTool:
			if s.Tool != "read_document" {
				return Request{}, fmt.Errorf("render: the experiment stages only read_document results, got %q", s.Tool)
			}
			if len(msgs) == 0 {
				user(ContinueTurn)
			}
			msgs = append(msgs,
				Message{Role: "assistant", Content: []Block{{Type: "tool_use", ID: readToolUseID, Name: s.Tool,
					Input: map[string]string{"id": in.DocumentID}}}},
				Message{Role: "user", Content: []Block{{Type: "tool_result", ToolUseID: readToolUseID, Content: s.Text}}})
		default:
			return Request{}, fmt.Errorf("render: unexpected %s span", s.Role)
		}
	}
	if len(msgs) == 0 {
		user(ContinueTurn)
	}
	return Request{
		Model:        p.Model,
		MaxTokens:    p.MaxTokens,
		System:       strings.Join(system, "\n\n"),
		Messages:     msgs,
		Tools:        tools(),
		OutputConfig: &OutputConfig{Effort: p.Effort},
	}, nil
}
