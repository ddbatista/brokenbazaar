package mode

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The vectors live in the gateway's tree and are read by BOTH languages'
// tests, so the Go and Python parsers are pinned to one table (M2-N4).
// A missing file fails the test: an absent contract must not read as
// agreement -- the same rule app/redact's drift test applies.
const vectorsPath = "../../gateway/mode_vectors.json"

type vector struct {
	Raw  string `json:"raw"`
	Want any    `json:"want"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("mode vectors unreadable (%v) -- the cross-language contract is missing", err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("mode vectors: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("mode vectors: empty -- a contract with no cases asserts nothing")
	}
	return doc.Vectors
}

func TestParseMatchesTheSharedVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		got, err := Parse(v.Raw)
		switch want := v.Want.(type) {
		case bool:
			if err != nil {
				t.Errorf("Parse(%q): unexpected error %v", v.Raw, err)
			} else if got != want {
				t.Errorf("Parse(%q) = %v, want %v", v.Raw, got, want)
			}
		case string:
			if want != "error" {
				t.Fatalf("vector %q: unknown want %q", v.Raw, want)
			}
			if err == nil {
				t.Errorf("Parse(%q) = %v, want a refusal -- a typo must not silently pick a mode", v.Raw, got)
			}
		default:
			t.Fatalf("vector %q: want has type %T", v.Raw, v.Want)
		}
	}
}

func TestFromEnvNamesTheVariableOnRefusal(t *testing.T) {
	t.Setenv("HARDENED", "ture")
	_, err := FromEnv()
	if err == nil {
		t.Fatal("FromEnv accepted HARDENED=ture")
	}
	if got := err.Error(); !strings.Contains(got, "HARDENED") || !strings.Contains(got, "ture") {
		t.Errorf("error %q should name the variable and the bad value", got)
	}
}
