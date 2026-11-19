// Package mcp is the platform's MCP-shaped subset (m4a D2): two
// JSON-RPC-shaped POSTs, tools/list and tools/call, hand-rolled stdlib
// because the protocol is the lesson. This file owns the MANIFEST
// contract -- the normative statement migration 004 glosses: the
// manifest is the COMPLETE tools/list response body, envelope included
// ({"jsonrpc":"2.0","id":…,"result":{"tools":[…]}}). Pinning is over raw
// bytes (T2 D1), and extraction would force a re-serialization Go and
// Python disagree on -- so nothing is ever extracted: what the server
// returned is what is hashed, stored, compared and eventually placed in
// the agent's context. The gateway's Python side parses the same shape
// (T5); each language parses its own copy and the digest comparison --
// never a shared parser -- is the security property.
//
// This is deliberately NOT an MCP client library. It knows the one
// envelope and the one manifest vocabulary this platform consumes, and
// refuses everything else loudly (SR-B6-7: bounded, failure non-fatal).
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
)

// The consent vocabulary, stated once (m4a D4): the data classes a tool
// may declare that it receives. Only polices classes ship -- a class the
// platform cannot check would be a lie the install UI tells on the
// publisher's behalf. user_text is declared-but-unverifiable per call
// (the platform cannot tell typed text from steered text -- finding 07's
// entire premise); document_content is enforceable through provenance.
const (
	ReceivesUserText        = "user_text"
	ReceivesDocumentContent = "document_content"
)

// Limits, all of them fail-closed (SR-B6-7: bounded in size, depth and
// time). Time is the caller's client timeout; size and shape are here.
const (
	MaxManifestBytes = 64 << 10 // a tools/list body larger than this is refused whole
	MaxDescription   = 2048     // a description is context bytes; bound it at the door
	MaxTools         = 64       // an installed server exposing more is refused
	MaxToolNameLen   = 64
)

// Tool is one entry of a manifest's tool list. Description is carried
// verbatim -- it is what the org reviews at install and what the agent's
// context will hold (SR-B9-13's one-rendering rule applied to listings).
type Tool struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Receives    []string `json:"receives"`
}

type envelope struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		Tools []Tool `json:"tools"`
	} `json:"result"`
}

// Parse validates a raw tools/list response body and returns its tools.
// It rejects, with a named error, everything the contract forbids: wrong
// size, a body that is not JSON, a missing or non-"2.0" jsonrpc field,
// a missing result.tools, too many tools, a missing or malformed name,
// a duplicate name, a missing or oversized description, or a receives
// list outside the vocabulary or with duplicates.
//
// The raw bytes are the caller's to keep: Parse never re-serializes, and
// the pin is over the bytes exactly as fetched (T2 D1).
func Parse(raw []byte) ([]Tool, error) {
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("mcp: manifest is %d bytes, over the %d limit", len(raw), MaxManifestBytes)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("mcp: manifest is not a tools/list response body: %w", err)
	}
	if env.JSONRPC != "2.0" {
		return nil, errors.New("mcp: manifest envelope is not jsonrpc 2.0")
	}
	if len(env.Result.Tools) == 0 {
		return nil, errors.New("mcp: manifest carries no tools")
	}
	if len(env.Result.Tools) > MaxTools {
		return nil, fmt.Errorf("mcp: manifest exposes %d tools, over the %d limit", len(env.Result.Tools), MaxTools)
	}
	seen := make(map[string]bool, len(env.Result.Tools))
	for i, t := range env.Result.Tools {
		if t.Name == "" || len(t.Name) > MaxToolNameLen {
			return nil, fmt.Errorf("mcp: tool %d has no name or a name over %d bytes", i, MaxToolNameLen)
		}
		for _, c := range t.Name {
			// Tool names become agent tool names and appear in the
			// ScriptedModel's grammar; keep them to the identifier shape
			// the grammar can match without escaping.
			if !(c == '_' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9') {
				return nil, fmt.Errorf("mcp: tool name %q is not lowercase identifier shape", t.Name)
			}
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("mcp: duplicate tool name %q", t.Name)
		}
		seen[t.Name] = true
		if t.Description == "" {
			return nil, fmt.Errorf("mcp: tool %q has no description", t.Name)
		}
		if len(t.Description) > MaxDescription {
			return nil, fmt.Errorf("mcp: tool %q description is %d bytes, over the %d limit", t.Name, len(t.Description), MaxDescription)
		}
		declared := make(map[string]bool, len(t.Receives))
		for _, class := range t.Receives {
			switch class {
			case ReceivesUserText, ReceivesDocumentContent:
			default:
				return nil, fmt.Errorf("mcp: tool %q declares unknown receives class %q", t.Name, class)
			}
			if declared[class] {
				return nil, fmt.Errorf("mcp: tool %q declares %q twice", t.Name, class)
			}
			declared[class] = true
		}
	}
	return env.Result.Tools, nil
}

// Receives reports whether tool declares class. Used by the install
// review payload (the org approves the vocabulary) and by T5's consent
// leg on the gateway side, through the authority route's facts.
func Receives(tool Tool, class string) bool {
	for _, c := range tool.Receives {
		if c == class {
			return true
		}
	}
	return false
}

// Request builds a JSON-RPC request body for the subset's two methods.
// The id is fixed: the lab's servers never multiplex, and a variable id
// would be one more thing the fixture and the client could disagree on.
func Request(method string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"` + method + `"}`)
}
