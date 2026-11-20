package auth_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/17xande-dev/budget/internal/auth"
	"github.com/17xande-dev/budget/internal/db"
	"github.com/17xande-dev/password"
)

func TestMain(m *testing.M) {
	password.SetParamsForTesting(password.Params{Memory: 64, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	os.Exit(m.Run())
}

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func newStore(t *testing.T) *auth.Store {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return auth.NewStore(d)
}

func hash(t *testing.T, pw string) string {
	t.Helper()
	h, err := auth.HashPassword(t.Context(), pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAuthenticate(t *testing.T) {
	s := newStore(t)
	if _, err := s.CreateUser("alex@example.com", "Alex", hash(t, "correct horse battery"), false, t0); err != nil {
		t.Fatal(err)
	}

	u, ok, err := s.Authenticate(t.Context(), "alex@example.com", "correct horse battery", t0)
	if err != nil || !ok {
		t.Fatalf("right password refused: ok=%v err=%v", ok, err)
	}
	if !u.LastLoginAt.Equal(t0) {
		t.Errorf("last login not recorded: %v", u.LastLoginAt)
	}
	// The column collates NOCASE: the login form must find the account however
	// the address was capitalised, or one person ends up with two identities.
	if _, ok, _ := s.Authenticate(t.Context(), "ALEX@example.com", "correct horse battery", t0); !ok {
		t.Error("email lookup is case-sensitive")
	}
	if _, ok, _ := s.Authenticate(t.Context(), "alex@example.com", "wrong", t0); ok {
		t.Error("wrong password accepted")
	}
	if _, ok, err := s.Authenticate(t.Context(), "nobody@example.com", "x", t0); ok || err != nil {
		t.Errorf("unknown email: ok=%v err=%v", ok, err)
	}
}

func TestCreateUserRefusesDuplicateEmail(t *testing.T) {
	s := newStore(t)
	h := hash(t, "correct horse battery")
	if _, err := s.CreateUser("a@example.com", "A", h, false, t0); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateUser("A@EXAMPLE.COM", "A again", h, false, t0)
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("duplicate (differently cased) email: got %v, want ErrEmailTaken", err)
	}
}

func TestPasswordWritesRejectInvalidHashes(t *testing.T) {
	// A valid bcrypt hash is supported by the module but never was by Budget.
	const bcryptHash = "$2a$10$twjQA8BMDdFuHP3afXoWe.PWv/NGS/A2zpHSrgDmWAVc/fzuPmJ66"
	if err := password.Validate(bcryptHash); err != nil {
		t.Fatalf("invalid bcrypt fixture: %v", err)
	}

	for _, tc := range []struct{ name, invalidHash string }{
		{"plaintext", "plaintext"},
		{"malformed Argon2id", "$argon2id$broken"},
		{"bcrypt", bcryptHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const email = "a@example.com"
			const goodPassword = "correct horse battery"

			t.Run("CreateUser", func(t *testing.T) {
				s := newStore(t)
				if _, err := s.CreateUser(email, "A", tc.invalidHash, false, t0); err == nil {
					t.Error("CreateUser accepted an invalid hash")
				}
				if _, found, err := s.FindByEmail(email); found || err != nil {
					t.Errorf("after rejected create: found=%v, err=%v", found, err)
				}
			})

			t.Run("SetPassword", func(t *testing.T) {
				s := newStore(t)
				u, err := s.CreateUser(email, "A", hash(t, goodPassword), false, t0)
				if err != nil {
					t.Fatal(err)
				}
				token, err := s.IssueSession(u.ID, t0, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if changed, err := s.SetPassword(u.ID, tc.invalidHash, false); changed || err == nil {
					t.Errorf("SetPassword accepted an invalid hash: changed=%v, err=%v", changed, err)
				}
				if ok, err := s.CheckUserPassword(t.Context(), u.ID, goodPassword); !ok || err != nil {
					t.Errorf("after rejected reset, current password: ok=%v, err=%v", ok, err)
				}
				if _, ok, err := s.VerifySession(token, t0); !ok || err != nil {
					t.Errorf("after rejected reset, existing session: ok=%v, err=%v", ok, err)
				}
			})

			t.Run("ClaimSetup", func(t *testing.T) {
				s := newStore(t)
				const token = "setup-token"
				if _, err := s.CreateSetupToken(token, t0); err != nil {
					t.Fatal(err)
				}
				if _, err := s.ClaimSetup(token, email, "A", tc.invalidHash, t0); err == nil {
					t.Error("ClaimSetup accepted an invalid hash")
				}
				if _, found, err := s.FindByEmail(email); found || err != nil {
					t.Errorf("after rejected claim: found=%v, err=%v", found, err)
				}
				if ok, err := s.CheckSetupToken(token); !ok || err != nil {
					t.Errorf("after rejected claim, setup token: ok=%v, err=%v", ok, err)
				}
			})
		})
	}
}

func TestSessions(t *testing.T) {
	s := newStore(t)
	u, err := s.CreateUser("a@example.com", "A", hash(t, "correct horse battery"), false, t0)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.IssueSession(u.ID, t0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.VerifySession(tok, t0.Add(time.Minute)); err != nil || !ok || got.ID != u.ID {
		t.Fatalf("fresh session refused: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.VerifySession(tok, t0.Add(time.Hour)); ok {
		t.Error("session accepted at its expiry instant")
	}
	if _, ok, _ := s.VerifySession("not-a-token", t0); ok {
		t.Error("unknown token accepted")
	}

	n, err := s.DeleteExpiredSessions(t0.Add(2 * time.Hour))
	if err != nil || n != 1 {
		t.Errorf("sweep: n=%d err=%v, want 1", n, err)
	}
}

// Changing a password is how you shut someone out, so it must end every session
// the old password opened -- including the one it was changed from.
func TestSetPasswordEndsSessions(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateUser("a@example.com", "A", hash(t, "correct horse battery"), true, t0)
	tok, _ := s.IssueSession(u.ID, t0, time.Hour)

	ok, err := s.SetPassword(u.ID, hash(t, "a whole new passphrase"), false)
	if err != nil || !ok {
		t.Fatalf("set password: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := s.VerifySession(tok, t0); ok {
		t.Error("session survived a password change")
	}
	got, ok, _ := s.Authenticate(t.Context(), "a@example.com", "a whole new passphrase", t0)
	if !ok {
		t.Fatal("new password refused")
	}
	if got.MustChangePassword {
		t.Error("must_change_password still set after choosing your own")
	}
	if ok, _ := s.SetPassword(999, hash(t, "a whole new passphrase"), false); ok {
		t.Error("SetPassword reported success for a nonexistent user")
	}
}

func TestSetupClaim(t *testing.T) {
	s := newStore(t)
	if pending, _ := s.SetupPending(); pending {
		t.Fatal("pending before any token was issued")
	}
	stored, err := s.CreateSetupToken("tok-1", t0)
	if err != nil || !stored {
		t.Fatalf("create token: stored=%v err=%v", stored, err)
	}
	// A second boot must not replace the live token.
	if stored, _ := s.CreateSetupToken("tok-2", t0); stored {
		t.Fatal("a second setup token replaced the first")
	}
	if pending, _ := s.SetupPending(); !pending {
		t.Fatal("not pending with an unspent token and no users")
	}

	h := hash(t, "correct horse battery")
	if _, err := s.ClaimSetup("tok-2", "a@example.com", "A", h, t0); !errors.Is(err, auth.ErrBadSetupToken) {
		t.Fatalf("wrong token: got %v", err)
	}
	u, err := s.ClaimSetup("tok-1", "a@example.com", "A", h, t0)
	if err != nil {
		t.Fatal(err)
	}
	if u.MustChangePassword {
		t.Error("the first account chose its own password and must not be forced to change it")
	}
	if stored, _, _ := s.FindByEmail("a@example.com"); !stored.LastLoginAt.Equal(t0) {
		t.Errorf("claiming signs you in but recorded last login %v", stored.LastLoginAt)
	}
	if _, err := s.ClaimSetup("tok-1", "b@example.com", "B", h, t0); !errors.Is(err, auth.ErrSetupClosed) {
		t.Fatalf("second claim with the same token: got %v, want ErrSetupClosed", err)
	}
	if pending, _ := s.SetupPending(); pending {
		t.Error("still pending after a claim")
	}
}

// An account arriving by another route (reset-password cannot create one, but a
// hand-run INSERT can) closes setup even with the token unspent.
func TestSetupClosedByExistingUser(t *testing.T) {
	s := newStore(t)
	s.CreateSetupToken("tok", t0)
	s.CreateUser("a@example.com", "A", hash(t, "correct horse battery"), false, t0)
	if pending, _ := s.SetupPending(); pending {
		t.Fatal("pending although a user exists")
	}
	if _, err := s.ClaimSetup("tok", "b@example.com", "B", hash(t, "correct horse battery"), t0); !errors.Is(err, auth.ErrSetupClosed) {
		t.Fatalf("claim with users present: got %v, want ErrSetupClosed", err)
	}
}
