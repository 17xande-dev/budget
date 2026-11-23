package handler_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/17xande-dev/password"
)

const rehashEmail = "legacy@example.com"

func legacyLogin(t *testing.T) (*env, int64, string) {
	t.Helper()
	e := newEnv(t)
	legacy, err := func() (string, error) {
		weak := password.DefaultParams
		weak.Time = 1
		defer password.SetParamsForTesting(weak)()
		return password.Hash(t.Context(), ownerPassword)
	}()
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.users.ClaimSetup(setupToken, rehashEmail, "Legacy", legacy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return e, u.ID, legacy
}

func storedLoginHash(t *testing.T, e *env, id int64) string {
	t.Helper()
	var hash string
	if err := e.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

func requireUsableLogin(t *testing.T, e *env, pw string) {
	t.Helper()
	b := e.browser()
	if r := b.login(rehashEmail, pw); r.code != http.StatusSeeOther || r.loc != "/" {
		t.Fatalf("login: got %d -> %q, want 303 -> /", r.code, r.loc)
	}
	if r := b.get("/"); r.code != http.StatusOK {
		t.Fatalf("login did not issue a usable session: got %d", r.code)
	}
}

func TestLoginUpgradesWeakHash(t *testing.T) {
	e, id, legacy := legacyLogin(t)
	requireUsableLogin(t, e, ownerPassword)
	got := storedLoginHash(t, e, id)
	if got == legacy {
		t.Fatal("login left the weak hash in place")
	}
	if ok, rehash, err := password.Check(t.Context(), got, ownerPassword); !ok || rehash || err != nil {
		t.Fatalf("upgraded hash: ok=%v, rehash=%v, err=%v; want a match at current parameters", ok, rehash, err)
	}
}

func TestLoginUpgradeDoesNotOverwriteConcurrentPasswordChange(t *testing.T) {
	e, id, legacy := legacyLogin(t)
	const newPassword = "a brand new passphrase"
	newHash, err := password.Hash(t.Context(), newPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(`CREATE TABLE test_password_change (old_hash TEXT NOT NULL, new_hash TEXT NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(`INSERT INTO test_password_change (old_hash, new_hash) VALUES (?, ?)`, legacy, newHash); err != nil {
		t.Fatal(err)
	}
	// Inject the competing write at the login bookkeeping statement, after
	// verification but before the upgrade, without depending on scheduling.
	if _, err := e.db.Exec(`CREATE TRIGGER test_change_after_verify AFTER UPDATE OF last_login_at ON users
		WHEN OLD.password_hash = (SELECT old_hash FROM test_password_change)
		BEGIN
			UPDATE users SET password_hash = (SELECT new_hash FROM test_password_change) WHERE id = OLD.id;
		END`); err != nil {
		t.Fatal(err)
	}
	requireUsableLogin(t, e, ownerPassword)
	if got := storedLoginHash(t, e, id); got != newHash {
		t.Fatal("the upgrade overwrote the competing password change")
	}
	requireUsableLogin(t, e, newPassword)
	if r := e.browser().login(rehashEmail, ownerPassword); r.code != http.StatusUnauthorized {
		t.Fatalf("old password after change: got %d, want 401", r.code)
	}
}

func TestLoginSucceedsIfHashUpgradeWriteFails(t *testing.T) {
	e, id, legacy := legacyLogin(t)
	// Reject password writes without breaking login bookkeeping or sessions.
	if _, err := e.db.Exec(`CREATE TRIGGER test_reject_upgrade BEFORE UPDATE OF password_hash ON users
		BEGIN SELECT RAISE(ABORT, 'test: password write rejected'); END`); err != nil {
		t.Fatal(err)
	}
	requireUsableLogin(t, e, ownerPassword)
	if got := storedLoginHash(t, e, id); got != legacy {
		t.Fatal("failed upgrade changed the stored hash")
	}
}
