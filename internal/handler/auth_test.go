package handler_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/17xande-dev/budget/internal/handler"
	"github.com/17xande-dev/password"
	"github.com/17xande-dev/ratelimit/clientip"
	"github.com/17xande-dev/websec/webtest"
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

func TestFailedLoginLogsOnlyAccountIDAndClientIP(t *testing.T) {
	source, err := clientip.ParseSource("cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, handler.Config{SessionTTL: time.Hour, ClientIPSource: source})
	e.claim()
	b := e.browser()
	token := b.token("/login")

	f, err := os.CreateTemp(t.TempDir(), "login-log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	old := log.Writer()
	log.SetOutput(f)
	t.Cleanup(func() { log.SetOutput(old) })

	const secret = "secret-pw-123"
	const email = "second@example.com"
	const ip = "203.0.113.7"
	attempt := func(address string) resp {
		t.Helper()
		form := url.Values{"email": {address}, "password": {"wrong password"}, "csrf_token": {token}}
		// The response's CSRF mask changes on each request. Hold it fixed
		// so only account existence could change the bytes of the response.
		cryptotest.SetGlobalRandom(t, 1)
		r := wrap(b.c.PostForm("/login", form, webtest.Header("CF-Connecting-IP", ip)))
		if r.code != http.StatusUnauthorized {
			t.Fatalf("failed login returned %d, want 401", r.code)
		}
		return r
	}
	attempt(secret)
	unknown := attempt(email)
	hash, err := password.Hash(t.Context(), ownerPassword)
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.users.CreateUser(email, "Second", hash, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	known := attempt(email)
	if unknown.body != known.body {
		t.Error("response body changed when the submitted address became known")
	}

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	logged := string(data)
	sum := sha256.Sum256([]byte(secret))
	// The marker is the log line the refusal path writes, so an empty log cannot pass.
	// NoSecrets also looks for each value's encoded forms (query, JSON, base64, hex).
	webtest.NoSecrets(t, logged, "unknown account client_ip="+ip,
		secret, fmt.Sprintf("%x", sum), base64.RawURLEncoding.EncodeToString(sum[:]), email)
	if n := strings.Count(logged, "unknown account client_ip="+ip); n != 2 {
		t.Errorf("got %d unknown-account entries with the resolved IP, want 2", n)
	}
	if !strings.Contains(logged, fmt.Sprintf("failed login user_id=%d client_ip=%s", u.ID, ip)) {
		t.Error("known-account failure did not log the user ID and resolved IP")
	}
}

func TestAuthCookieAttributes(t *testing.T) {
	const ttl = 2 * time.Hour
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("secure=%t", secure), func(t *testing.T) {
			e := newEnvWith(t, handler.Config{SessionTTL: ttl, CookieSecure: secure})
			e.claim()
			b := e.browser()

			loginPage := b.get("/login")
			if loginPage.code != http.StatusOK {
				t.Fatalf("GET /login: got %d, want 200", loginPage.code)
			}
			// The kit names the CSRF cookie __Host-csrf_token on https.
			csrfName := map[bool]string{true: "__Host-csrf_token", false: "csrf_token"}[secure]
			csrf := webtest.WantCookie(t, loginPage.res, webtest.CookieWant{
				Name: csrfName, Path: "/", Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			if csrf.Value == "" {
				t.Error("GET /login: CSRF cookie is empty")
			}

			earliestExpiry := time.Now().Add(ttl).Truncate(time.Second)
			login := b.login("owner@example.com", ownerPassword)
			if login.code != http.StatusSeeOther || login.loc != "/" {
				t.Fatalf("POST /login: got %d -> %q, want 303 -> /", login.code, login.loc)
			}
			sessionName := map[bool]string{true: "__Host-budget_session", false: "budget_session"}[secure]
			session := webtest.WantCookie(t, login.res, webtest.CookieWant{
				Name: sessionName, Path: "/", Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			latestExpiry := time.Now().Add(ttl)
			// The kit floors Max-Age to whole seconds, so it may read a second short.
			if session.Value == "" || session.MaxAge > int(ttl.Seconds()) || session.MaxAge < int(ttl.Seconds())-2 ||
				session.Expires.Before(earliestExpiry) || session.Expires.After(latestExpiry) {
				t.Errorf("POST /login: nonempty=%t MaxAge=%d Expires=%s, want a nonempty %s session",
					session.Value != "", session.MaxAge, session.Expires, ttl)
			}

			logout := b.post("/", "/logout", nil)
			if logout.code != http.StatusSeeOther || logout.loc != "/login" {
				t.Fatalf("POST /logout: got %d -> %q, want 303 -> /login", logout.code, logout.loc)
			}
			cleared := webtest.WantCookie(t, logout.res, webtest.CookieWant{
				Name: sessionName, Path: "/", Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode, Cleared: true,
			})
			// The kit also sets Expires to the epoch, for clients that ignore Max-Age.
			if cleared.Value != "" || cleared.MaxAge >= 0 || cleared.Expires.Unix() != 0 {
				t.Errorf("POST /logout: empty=%t MaxAge=%d Expires=%s, want an empty cookie with negative MaxAge and an epoch Expires",
					cleared.Value == "", cleared.MaxAge, cleared.Expires)
			}
		})
	}
}
