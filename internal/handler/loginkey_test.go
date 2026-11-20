package handler

import (
	"strings"
	"testing"
)

func TestLoginEmailKey(t *testing.T) {
	if got := loginEmailKey("Owner@Example.com"); got != "email:owner@example.com" {
		t.Errorf("short key = %q", got)
	}
	long := strings.Repeat("a", 5000) + "@example.com"
	k1, k2 := loginEmailKey(long), loginEmailKey(long+"x")
	if len(k1) > 256 || k1 == k2 {
		t.Errorf("long keys: len %d, distinct=%v; want <=256 and distinct", len(k1), k1 != k2)
	}
	if k1 != loginEmailKey(strings.ToUpper(long)) {
		t.Error("hashed key is case sensitive; the short form is not")
	}
}
