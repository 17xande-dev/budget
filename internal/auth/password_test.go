package auth_test

import (
	"testing"

	"github.com/17xande-dev/budget/internal/auth"
)

func TestHashPasswordRejectsEmpty(t *testing.T) {
	if _, err := auth.HashPassword(t.Context(), ""); err == nil || err.Error() != "auth: password must not be empty" {
		t.Errorf("empty password: got %v, want the app's empty-password error", err)
	}
}
