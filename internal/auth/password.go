// Package auth authenticates the people who use the budget.
//
// Sessions are opaque random tokens in a database table -- see store.go. A
// signed cookie would still need the table to invalidate sessions on password
// change, and would add a signing key and a rotation runbook for nothing.
package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/17xande-dev/password"
)

// HashPassword refuses empty passwords even when called outside a form.
func HashPassword(ctx context.Context, pw string) (string, error) {
	if pw == "" {
		return "", errors.New("auth: password must not be empty")
	}
	return password.Hash(ctx, pw)
}

func validatePasswordHash(hash string) error {
	// Budget has only ever accepted Argon2id credentials, not legacy bcrypt.
	if !strings.HasPrefix(hash, "$argon2id$") {
		return errors.New("auth: unrecognised password hash format: expected a $argon2id$ hash (set one with `budget reset-password`)")
	}
	return password.Validate(hash)
}

func checkPassword(ctx context.Context, hash, pw string) bool {
	if !strings.HasPrefix(hash, "$argon2id$") {
		return false
	}
	// A malformed stored hash is indistinguishable from a wrong password to
	// the visitor, and must count toward the same login rate limit.
	ok, _, err := password.Check(ctx, hash, pw)
	return err == nil && ok
}
