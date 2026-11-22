package mcp

import (
	"strings"
	"testing"
)

const good = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"summarize_notes","description":"Summarizes the notes you paste as the query argument.","receives":["user_text"]}]}}`

// TestParseAcceptsTheContract pins the one shape the platform consumes:
// the FULL tools/list response, envelope included (T3 D1 -- nothing is
// ever extracted, because extraction would re-serialize).
func TestParseAcceptsTheContract(t *testing.T) {
	tools, err := Parse([]byte(good))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "summarize_notes" {
		t.Fatalf("tools = %+v", tools)
	}
	if !Receives(tools[0], ReceivesUserText) || Receives(tools[0], ReceivesDocumentContent) {
		t.Fatal("Receives disagrees with the declared vocabulary")
	}
}

// TestParseRefuses pins every refusal the contract names. Each case is a
// distinct SR-B6-7 failure, and the bare document is deliberately first:
// T2's first seed wrote manifests WITHOUT the envelope, and this test is
// what keeps that shape from quietly returning.
func TestParseRefuses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"bare tools document, no envelope (T2's first seed shape)", `{"tools":[{"name":"t","description":"d","receives":["user_text"]}]}`},
		{"not json", `not json`},
		{"wrong jsonrpc", `{"jsonrpc":"1.0","id":1,"result":{"tools":[{"name":"t","description":"d","receives":[]}]}}`},
		{"no tools", `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`},
		{"no result", `{"jsonrpc":"2.0","id":1}`},
		{"no name", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"description":"d","receives":[]}]}}`},
		{"uppercase name", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"BadName","description":"d","receives":[]}]}}`},
		{"duplicate names", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d","receives":[]},{"name":"t","description":"d2","receives":[]}]}}`},
		{"no description", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","receives":[]}]}}`},
		{"oversized description", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"` + strings.Repeat("x", MaxDescription+1) + `","receives":[]}]}}`},
		{"unknown receives class", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d","receives":["keystrokes"]}]}}`},
		{"duplicate receives", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d","receives":["user_text","user_text"]}]}}`},
		{"too many tools", `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + strings.Repeat(`{"name":"t","description":"d","receives":[]},`, MaxTools) + `{"name":"t2","description":"d","receives":[]}]}}`},
	}
	for _, tc := range cases {
		if _, err := Parse([]byte(tc.body)); err == nil {
			t.Errorf("%s: Parse accepted a body the contract refuses", tc.name)
		}
	}
}

// TestParseRefusesOversizedBody is its own case because the body is
// built from bytes, not a string literal.
func TestParseRefusesOversizedBody(t *testing.T) {
	body := append([]byte(good[:len(good)-2]), []byte(strings.Repeat(" ", MaxManifestBytes))...)
	body = append(body, '"', '}')
	if _, err := Parse(body); err == nil {
		t.Fatal("Parse accepted a body over the size limit")
	}
}

// TestRequestPinsTheWireShape: the two methods this subset speaks, with
// a fixed id, because a variable the fixture and client could disagree
// on is one variable too many.
func TestRequestPinsTheWireShape(t *testing.T) {
	if got, want := string(Request("tools/list")), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`; got != want {
		t.Fatalf("Request = %s, want %s", got, want)
	}
}
