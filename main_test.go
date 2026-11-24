package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/budget/internal/auth"
	"github.com/17xande-dev/budget/internal/config"
	"github.com/17xande-dev/budget/internal/db"
	"github.com/17xande-dev/password"
)

func TestMain(m *testing.M) {
	password.SetParamsForTesting(password.Params{Memory: 64, Time: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	os.Exit(m.Run())
}

func newStore(t *testing.T) *auth.Store {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "main.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return auth.NewStore(d)
}

func TestEnsureSetupTokenPrintsGeneratedToken(t *testing.T) {
	s := newStore(t)
	var buf bytes.Buffer
	if err := ensureSetupToken(s, "", log.New(&buf, "", 0)); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	i := strings.LastIndex(line, ": ")
	if i < 0 {
		t.Fatalf("no token in log line %q", line)
	}
	token := strings.TrimSpace(line[i+2:])
	// The printed token must be the one that actually works.
	if ok, _ := s.CheckSetupToken(token); !ok {
		t.Fatalf("logged token %q does not claim setup", token)
	}

	// A restart must not issue a second token or reprint anything usable.
	buf.Reset()
	ensureSetupToken(s, "", log.New(&buf, "", 0))
	if strings.Contains(buf.String(), token) {
		t.Error("a restart reprinted the token")
	}
	if ok, _ := s.CheckSetupToken(token); !ok {
		t.Error("a restart invalidated the first token")
	}
}

func TestEnsureSetupTokenWarnsOnMismatchedSupplied(t *testing.T) {
	s := newStore(t)
	ensureSetupToken(s, "", log.New(&bytes.Buffer{}, "", 0))
	var buf bytes.Buffer
	ensureSetupToken(s, strings.Repeat("x", 40), log.New(&buf, "", 0))
	if !strings.Contains(buf.String(), "does not match") {
		t.Errorf("no warning for a SETUP_TOKEN that cannot work: %q", buf.String())
	}
}

func TestEnsureSetupTokenSilentOnceClaimed(t *testing.T) {
	s := newStore(t)
	h, err := auth.HashPassword(t.Context(), "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	s.CreateUser("a@example.com", "A", h, false, time.Now())
	var buf bytes.Buffer
	ensureSetupToken(s, "", log.New(&buf, "", 0))
	if buf.Len() != 0 {
		t.Errorf("logged on a claimed deployment: %q", buf.String())
	}
}

func TestResetPassword(t *testing.T) {
	s := newStore(t)
	h, err := auth.HashPassword(t.Context(), "the old passphrase")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.CreateUser("a@example.com", "A", h, true, time.Now())
	tok, _ := s.IssueSession(u.ID, time.Now(), time.Hour)

	var out bytes.Buffer
	if err := resetPassword(s, "A@example.com", strings.NewReader("a brand new passphrase\n"), &out); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := s.Authenticate(t.Context(), "a@example.com", "a brand new passphrase", time.Now())
	if !ok {
		t.Fatal("new password does not work")
	}
	if got.MustChangePassword {
		t.Error("a password the owner set themselves is marked must-change")
	}
	if _, ok, _ := s.VerifySession(tok, time.Now()); ok {
		t.Error("an old session survived a reset")
	}

	// Same policy as the web forms.
	if err := resetPassword(s, "a@example.com", strings.NewReader("short\n"), &out); err == nil {
		t.Error("a short password was accepted")
	}
	// Never creates an account.
	if err := resetPassword(s, "nobody@example.com", strings.NewReader("a brand new passphrase\n"), &out); err == nil {
		t.Error("reset for an unknown address succeeded")
	}
}

// Header values key the rate limiters, so the server must not accept the default
// 1 MB of them.
func TestServerCapsHeaders(t *testing.T) {
	srv := newServer(":0", http.NotFoundHandler())
	if srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 64<<10)
	}
}

func request(h http.Handler, peer string, hdr map[string]string) int {
	r := httptest.NewRequest("POST", "/login", nil)
	r.RemoteAddr = peer
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// The secret-route limiter main builds takes its client address from the
// configured CLIENT_IP_SOURCE: through config.Load and newSecretLimit, the same
// path run() uses. A zero Source (the bug this pins) would put every client
// behind the proxy in one bucket.
func TestSecretLimitUsesConfiguredClientIPSource(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	build := func(env string) http.Handler {
		t.Setenv("CLIENT_IP_SOURCE", env)
		t.Setenv("PUBLIC_URL", "https://budget.example.com")
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		limit, err := newSecretLimit(cfg.ClientIPSource)
		if err != nil {
			t.Fatal(err)
		}
		return limit(ok)
	}

	// cloudflare: 11 distinct clients behind one peer all get through (the burst
	// is 10 per client), and one client is cut off on its 11th request.
	h := build("cloudflare")
	for i := range 11 {
		if code := request(h, "10.0.0.1:1", map[string]string{"CF-Connecting-IP": "203.0.113." + strconv.Itoa(i+1)}); code != 200 {
			t.Fatalf("cloudflare: distinct client %d refused (%d)", i, code)
		}
	}
	h = build("cloudflare")
	for i := range 10 {
		if code := request(h, "10.0.0.1:1", map[string]string{"CF-Connecting-IP": "198.51.100.9"}); code != 200 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code := request(h, "10.0.0.1:1", map[string]string{"CF-Connecting-IP": "198.51.100.9"}); code != 429 {
		t.Errorf("11th request from one client = %d, want 429", code)
	}

	// remote (and so a spoofed header): the peer is the client.
	h = build("remote")
	var last int
	for i := range 11 {
		last = request(h, "10.0.0.1:1", map[string]string{"CF-Connecting-IP": "203.0.113." + strconv.Itoa(i+1)})
	}
	if last != 429 {
		t.Errorf("remote: rotating CF-Connecting-IP escaped the limit (%d)", last)
	}

	// The secret limiter is fail-closed at a full table: the 10,001st address is refused.
	h = build("remote")
	for i := range 10_000 {
		peer := "10." + strconv.Itoa(i/65536) + "." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256) + ":1"
		if code := request(h, peer, nil); code != 200 {
			t.Fatalf("address %d refused below the cap (%d)", i, code)
		}
	}
	if code := request(h, "192.0.2.1:1", nil); code != 429 {
		t.Errorf("an unseen address at a full table = %d, want 429", code)
	}
}
