package store

import "testing"

func TestIsID(t *testing.T) {
	if !IsID(NewID()) {
		t.Error("an id this store minted is not an id")
	}
	for _, s := range []string{"", "nope", "s-1", "0A000000-0000-4000-8000-000000000001",
		"0a000000-0000-4000-8000-00000000000", "0a000000_0000-4000-8000-000000000001",
		"0a000000-0000-4000-8000-000000000001/../x"} {
		if IsID(s) {
			t.Errorf("IsID(%q) = true", s)
		}
	}
}
