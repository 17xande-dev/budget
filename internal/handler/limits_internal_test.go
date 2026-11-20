package handler

import (
	"strconv"
	"testing"
)

// The per-email tier is fail-closed: once the table holds its cap of keys, an
// unseen address is refused (Allow and Exhausted both), not admitted untracked.
// An address already tracked keeps using its own bucket.
func TestLoginByEmailFailsClosedWhenFull(t *testing.T) {
	h, err := New(nil, nil, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	l := h.loginByEmail
	const cap = 10_000
	for i := range cap {
		if !l.Allow("email:fill" + strconv.Itoa(i)) {
			t.Fatalf("key %d refused below the cap", i)
		}
	}
	if l.Len() != cap {
		t.Fatalf("Len = %d, want %d", l.Len(), cap)
	}
	if !l.Exhausted("email:unseen@example.com") {
		t.Error("an unseen key was not reported exhausted at a full table")
	}
	if l.Allow("email:unseen@example.com") {
		t.Error("an unseen key was admitted at a full table")
	}
	if l.Len() != cap {
		t.Errorf("Len = %d after refusals, want %d", l.Len(), cap)
	}
	if !l.Allow("email:fill0") {
		t.Error("a tracked key was refused at a full table")
	}
}
