package handler_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/budget/internal/handler"
)

const (
	csrfCookie    = "__Host-csrf_token"     // the kit's name on https
	sessionCookie = "__Host-budget_session" // __Host- on https
)

func (b *browser) cookie(name string) string {
	b.e.t.Helper()
	u, _ := url.Parse(b.e.srv.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (b *browser) refusedWith(path, token string) {
	b.e.t.Helper()
	r := b.postRaw(path, url.Values{"csrf_token": {token}})
	if r.code != http.StatusForbidden {
		b.e.t.Fatalf("POST %s with a stale token: %d, want 403", path, r.code)
	}
}

// Signing in, changing the password and signing out each replace the CSRF
// cookie, and the token issued before the change is refused afterwards.
func TestCredentialChangesRenewTheCSRFToken(t *testing.T) {
	e := newEnvWith(t, handler.Config{SessionTTL: time.Hour, CookieSecure: true})
	b := e.browser()

	// Setup claim is the first sign-in.
	preToken := b.token("/setup")
	preCookie := b.cookie(csrfCookie)
	if preCookie == "" {
		t.Fatal("no CSRF cookie before sign-in")
	}
	r := b.postRaw("/setup", url.Values{
		"csrf_token": {preToken}, "token": {setupToken}, "email": {"owner@example.com"}, "name": {"Owner"},
		"password": {ownerPassword}, "password_confirm": {ownerPassword},
	})
	if r.code != http.StatusSeeOther {
		t.Fatalf("setup: %d %s", r.code, r.body)
	}
	if got := b.cookie(csrfCookie); got == "" || got == preCookie {
		t.Fatal("sign-in kept the CSRF cookie")
	}
	b.refusedWith("/logout", preToken)
	if r := b.get("/"); r.code != http.StatusOK {
		t.Fatalf("a refused logout ended the session: %d", r.code)
	}

	// Own password change.
	signedIn, signedInCookie := b.token("/password"), b.cookie(csrfCookie)
	r = b.postRaw("/password", url.Values{"csrf_token": {signedIn}, "current": {ownerPassword},
		"password": {"a brand new passphrase"}, "password_confirm": {"a brand new passphrase"}})
	if r.code != http.StatusSeeOther {
		t.Fatalf("password change: %d %s", r.code, r.body)
	}
	if got := b.cookie(csrfCookie); got == "" || got == signedInCookie {
		t.Fatal("password change kept the CSRF cookie")
	}
	b.refusedWith("/login", signedIn)

	// Sign in again, then out.
	loginToken, loginCookie := b.token("/login"), b.cookie(csrfCookie)
	if r := b.postRaw("/login", url.Values{"csrf_token": {loginToken}, "email": {"owner@example.com"}, "password": {"a brand new passphrase"}}); r.code != http.StatusSeeOther {
		t.Fatalf("login: %d %s", r.code, r.body)
	}
	if got := b.cookie(csrfCookie); got == "" || got == loginCookie {
		t.Fatal("login kept the CSRF cookie")
	}
	b.refusedWith("/members", loginToken)
	beforeLogout, beforeCookie := b.token("/"), b.cookie(csrfCookie)
	if r := b.postRaw("/logout", url.Values{"csrf_token": {beforeLogout}}); r.code != http.StatusSeeOther {
		t.Fatalf("logout: %d", r.code)
	}
	if got := b.cookie(csrfCookie); got == "" || got == beforeCookie {
		t.Fatal("sign-out kept the CSRF cookie")
	}
	b.refusedWith("/login", beforeLogout)
}

// A session cookie under the old bare name is not read: its owner is signed out,
// whatever it holds.
func TestBareNamedSessionCookieIsIgnored(t *testing.T) {
	e := newEnvWith(t, handler.Config{SessionTTL: time.Hour, CookieSecure: true})
	b := e.claim()
	valid := b.cookie(sessionCookie)
	if valid == "" {
		t.Fatal("no __Host- session cookie after sign-in")
	}
	get := func(name string) resp {
		req, _ := http.NewRequest("GET", e.srv.URL+"/settings", nil)
		req.AddCookie(&http.Cookie{Name: name, Value: valid})
		return e.browser().do(req) // a fresh jar: only the cookie above is sent
	}
	if r := get("budget_session"); r.code != http.StatusSeeOther || !strings.HasPrefix(r.loc, "/login") {
		t.Fatalf("a bare-named session cookie signed someone in: %d -> %q", r.code, r.loc)
	}
	if r := get(sessionCookie); r.code != http.StatusOK {
		t.Fatalf("the prefixed cookie was refused: %d", r.code)
	}
}

// Startup refuses a public origin the kit cannot match.
func TestNewRefusesAMalformedPublicOrigin(t *testing.T) {
	for _, origin := range []string{"", "https://Budget.example", "https://budget.example/", "https://budget.example:443"} {
		e := func() error {
			_, err := handler.New(nil, nil, nil, handler.Config{PublicOrigin: origin, CookieSecure: true})
			return err
		}()
		if e == nil {
			t.Errorf("%q accepted", origin)
		}
	}
}
