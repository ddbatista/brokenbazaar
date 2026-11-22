package skill

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func knownTools(tools ...string) func(string) bool {
	return func(t string) bool {
		for _, k := range tools {
			if t == k {
				return true
			}
		}
		return false
	}
}

// realVocabulary mirrors what the store will pass: every platform tool
// the session vocabulary knows. The parser never copies the list.
var realVocabulary = knownTools("read_document", "create_document", "update_document", "delete_document", "http_fetch", "set_member_role")

func TestParseVector(t *testing.T) {
	idx, err := ParseFrontmatter([]byte(ExampleBundle), realVocabulary)
	if err != nil {
		t.Fatalf("canonical bundle rejected: %v", err)
	}
	if idx.Name != "meeting-notes" {
		t.Errorf("name = %q, want meeting-notes", idx.Name)
	}
	if idx.Description != "Prepare meeting notes from a document the user names." {
		t.Errorf("description = %q", idx.Description)
	}
	if len(idx.Triggers) != 1 || !strings.HasPrefix(idx.Triggers[0], "use when the user asks") {
		t.Errorf("triggers = %v", idx.Triggers)
	}
	if len(idx.Capabilities) != 2 || idx.Capabilities[0] != "read_document" || idx.Capabilities[1] != "update_document" {
		t.Errorf("capabilities = %v", idx.Capabilities)
	}
	if len(idx.References) != 0 {
		// references is optional; the parse holds an EMPTY list, not nil,
		// so the jsonb round-trip is stable ([] not null).
		t.Errorf("references = %v, want empty", idx.References)
	}
	if !strings.Contains(idx.Body, "titled Notes: at the end") {
		t.Errorf("body = %q", idx.Body)
	}
}

// TestDigestVector pins the canonical bundle's sha256. The Python
// fixture family must match these EXACT bytes (one bundle, one hex,
// two languages -- the mcp manifest vector's rule, m4a D3).
func TestDigestVector(t *testing.T) {
	sum := sha256.Sum256([]byte(ExampleBundle))
	got := hex.EncodeToString(sum[:])
	want := "e1f06dcd6f369f47eea7738a1a3113cc0de7f2293087c63fbba16696d0e34c79"
	if got != want {
		t.Fatalf("ExampleBundle digest = %s, want %s (the seed and the fixtures follow these bytes)", got, want)
	}
}

// TestReferencesParseAndHold asserts the declared fetch surface: a
// reference skill parses with its URLs held as written, and the empty
// list serializes stably.
func TestReferencesParseAndHold(t *testing.T) {
	bundle := "---\nname: ref-helper\ndescription: \"Formats notes.\"\ntriggers:\n  - \"use when formatting\"\ncapabilities:\n  - read_document\nreferences:\n  - https://publisher.example/reference.md\n---\nSee the reference for details.\n"
	idx, err := ParseFrontmatter([]byte(bundle), realVocabulary)
	if err != nil {
		t.Fatalf("bundle with a reference rejected: %v", err)
	}
	if len(idx.References) != 1 || idx.References[0] != "https://publisher.example/reference.md" {
		t.Fatalf("references = %v", idx.References)
	}
}

func TestRejections(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
		substr string
	}{
		{"no opening fence", "name: x\n", "must open with a --- line"},
		{"never closed", "---\nname: x\n", "never closed"},
		{"unknown key", "---\nname: x\npriority: 1\n---\nbody\n", "unknown key"},
		{"repeated key", "---\nname: x\nname: y\n---\nbody\n", "repeated"},
		{"bad name charset", "---\nname: Notes!\ndescription: \"d\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n", "only [a-z0-9_-]"},
		{"missing description", "---\nname: x\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n", "description is required"},
		{"decomposed description", "---\nname: x\ndescription: \"cafe\u0301 notes\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n", "combining mark"},
		{"bidi description", "---\nname: x\ndescription: \"notes \u202Eevil\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n", "non-printing"},
		{"mixed scripts", "---\nname: x\ndescription: \"\u043E\u0431\u044B\u0447\u043D\u044B\u0435 notes\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n", "mixed scripts"},
		{"no triggers", "---\nname: x\ndescription: \"d\"\ncapabilities:\n  - read_document\n---\nbody\n", "at least one trigger"},
		{"no capabilities", "---\nname: x\ndescription: \"d\"\ntriggers:\n  - \"t\"\n---\nbody\n", "capabilities is required"},
		{"unknown capability", "---\nname: x\ndescription: \"d\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - install_tool\n---\nbody\n", "not a platform tool"},
		{"bad reference", "---\nname: x\ndescription: \"d\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\nreferences:\n  - publisher.example/reference.md\n---\nbody\n", "absolute http(s) URL"},
		{"empty body", "---\nname: x\ndescription: \"d\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\n\n", "body is required"},
		{"list outside a list", "---\nname: x\n- orphan\ndescription: \"d\"\n---\nbody\n", "outside a list"},
		{"quote inside quoted", "---\nname: x\ndescription: \"say \"hi\" now\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - read_document\n---\nbody\n", "quote inside a quoted scalar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFrontmatter([]byte(tc.bundle), realVocabulary)
			if err == nil {
				t.Fatalf("bundle accepted, want a rejection containing %q", tc.substr)
			}
			if !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("err = %q, want it to contain %q", err.Error(), tc.substr)
			}
		})
	}
}

// TestVocabularyIsTheCallers proves the parser holds no copied tool
// list: the SAME bundle parses under one vocabulary and is refused
// under a narrower one, because the caller said so.
func TestVocabularyIsTheCallers(t *testing.T) {
	bundle := "---\nname: x\ndescription: \"d\"\ntriggers:\n  - \"t\"\ncapabilities:\n  - http_fetch\n---\nbody\n"
	if _, err := ParseFrontmatter([]byte(bundle), realVocabulary); err != nil {
		t.Fatalf("http_fetch is a real platform tool: %v", err)
	}
	if _, err := ParseFrontmatter([]byte(bundle), knownTools("read_document")); err == nil {
		t.Fatal("accepted http_fetch under a vocabulary that does not know it -- the caller's word is the ceiling's vocabulary")
	}
}
