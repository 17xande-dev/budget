package mcpserver

import (
	"strconv"
	"testing"

	"github.com/17xande-dev/ratelimit"
)

// Both MCP limiters are fail-closed: at the key cap an unseen address is refused,
// so a flood of fresh addresses cannot switch either tier off.
func TestMCPLimitersFailClosedWhenFull(t *testing.T) {
	s, err := New(Deps{})
	if err != nil {
		t.Fatal(err)
	}
	const cap = 10_000
	for name, l := range map[string]*ratelimit.Limiter{"calls": s.calls, "failures": s.failures} {
		t.Run(name, func(t *testing.T) {
			for i := range cap {
				if !l.Allow("k" + strconv.Itoa(i)) {
					t.Fatalf("key %d refused below the cap", i)
				}
			}
			if l.Allow("unseen") {
				t.Error("an unseen key was admitted at a full table")
			}
			if !l.Exhausted("unseen") {
				t.Error("an unseen key was not reported exhausted at a full table")
			}
			if l.Len() != cap {
				t.Errorf("Len = %d, want %d", l.Len(), cap)
			}
			if !l.Allow("k0") {
				t.Error("a tracked key was refused at a full table")
			}
		})
	}
}
