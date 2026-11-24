package config

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Cookies default to Secure, which makes PUBLIC_URL required; the tests that are
// not about it run with one set.
func TestMain(m *testing.M) {
	os.Setenv("PUBLIC_URL", "https://budget.example.com")
	os.Exit(m.Run())
}

func TestPublicURL(t *testing.T) {
	t.Run("required while cookies are Secure", func(t *testing.T) {
		t.Setenv("PUBLIC_URL", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PUBLIC_URL") {
			t.Fatalf("got %v, want an error naming PUBLIC_URL", err)
		}
	})
	t.Run("plain-http development defaults to localhost on the port", func(t *testing.T) {
		t.Setenv("PUBLIC_URL", "")
		t.Setenv("COOKIE_SECURE", "false")
		t.Setenv("PORT", "9090")
		if c, err := Load(); err != nil || c.PublicOrigin != "http://localhost:9090" {
			t.Fatalf("got %q, %v", c.PublicOrigin, err)
		}
	})
	for raw, want := range map[string]string{
		"https://budget.example.com":      "https://budget.example.com",
		" HTTPS://Budget.Example.com/ ":   "https://budget.example.com",
		"https://budget.example.com:443":  "https://budget.example.com",
		"https://budget.example.com:8443": "https://budget.example.com:8443",
	} {
		t.Run("accepts "+raw, func(t *testing.T) {
			t.Setenv("PUBLIC_URL", raw)
			if c, err := Load(); err != nil || c.PublicOrigin != want {
				t.Fatalf("got %q, %v, want %q", c.PublicOrigin, err, want)
			}
		})
	}
	for _, raw := range []string{"budget.example.com", "https://budget.example.com/app", "https://u:p@budget.example.com", "https://budget.example.com?x=1", "ftp://budget.example.com", "http://budget.example.com"} {
		t.Run("refuses "+raw, func(t *testing.T) {
			t.Setenv("PUBLIC_URL", raw)
			if _, err := Load(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.CookieSecure {
		t.Error("cookies must default to Secure")
	}
	if c.SessionTTL != 30*24*time.Hour || c.Port != "8080" || c.DBPath != "data/budget.db" {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

// A typo must not quietly mean "insecure".
func TestCookieSecureIsStrict(t *testing.T) {
	t.Setenv("COOKIE_SECURE", "ture")
	if _, err := Load(); err == nil {
		t.Fatal("COOKIE_SECURE=ture was accepted")
	}
	t.Setenv("COOKIE_SECURE", "false")
	if c, err := Load(); err != nil || c.CookieSecure {
		t.Fatalf("COOKIE_SECURE=false: secure=%v err=%v", c.CookieSecure, err)
	}
}

func TestBadSessionTTL(t *testing.T) {
	t.Setenv("SESSION_TTL", "-1h")
	if _, err := Load(); err == nil {
		t.Fatal("a negative session TTL was accepted")
	}
}

func TestShortSetupTokenIgnored(t *testing.T) {
	t.Setenv("SETUP_TOKEN", "short")
	c, _ := Load()
	if c.SetupToken != "" {
		t.Error("a short SETUP_TOKEN was kept")
	}
	t.Setenv("SETUP_TOKEN", "  "+strings.Repeat("x", MinSetupTokenLength)+"\n")
	c, _ = Load()
	if c.SetupToken != strings.Repeat("x", MinSetupTokenLength) {
		t.Errorf("a long SETUP_TOKEN was not kept trimmed: %q", c.SetupToken)
	}
}

func TestClientIPSource(t *testing.T) {
	// A request from a fixed peer carrying a spoofable CF-Connecting-IP: the key
	// the configured source reads from it tells the sources apart.
	addr := func(c Config) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		r.Header.Set("CF-Connecting-IP", "203.0.113.7")
		r.Header.Set("X-Forwarded-For", "198.51.100.2")
		return c.ClientIPSource.Addr(r).String()
	}

	c, err := Load()
	if err != nil || addr(c) != "10.0.0.1" {
		t.Errorf("default = %q, %v; want the peer", addr(c), err)
	}

	t.Setenv("CLIENT_IP_SOURCE", "cloudflare")
	if c, err := Load(); err != nil || addr(c) != "203.0.113.7" {
		t.Errorf("cloudflare: %q, %v; want CF-Connecting-IP", addr(c), err)
	}

	t.Setenv("CLIENT_IP_SOURCE", "forwarded")
	if c, err := Load(); err != nil || addr(c) != "198.51.100.2" {
		t.Errorf("forwarded: %q, %v; want X-Forwarded-For", addr(c), err)
	}

	t.Setenv("CLIENT_IP_SOURCE", "remote")
	if c, err := Load(); err != nil || addr(c) != "10.0.0.1" {
		t.Errorf("remote: %q, %v; want the peer", addr(c), err)
	}

	t.Setenv("CLIENT_IP_SOURCE", "everyone")
	if _, err := Load(); err == nil {
		t.Error("an unknown CLIENT_IP_SOURCE was accepted")
	}
}

// The old setting is refused, not ignored: dropping it quietly would leave a
// deployment believing it still had per-client limits.
func TestTrustedProxiesIsRefused(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "172.16.0.0/12")
	if _, err := Load(); err == nil {
		t.Error("TRUSTED_PROXIES was accepted")
	}
}

func TestFNB(t *testing.T) {
	dir := t.TempDir()
	secret := dir + "/fnb_password"
	os.WriteFile(secret, []byte("hunter2-not-really\n"), 0o600)

	t.Setenv("FNB_USERNAME", "someone")
	t.Setenv("FNB_PASSWORD_FILE", secret)
	t.Setenv("FETCH_AT", "05:30")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.FNB.Password != "hunter2-not-really" || c.FNB.Hour != 5 || c.FNB.Minute != 30 || len(c.FNB.Products) != 2 {
		t.Errorf("fnb config: %+v", c.FNB)
	}

	// A password in a plain environment variable is refused, not used.
	t.Setenv("FNB_PASSWORD", "plain")
	if _, err := Load(); err == nil {
		t.Error("FNB_PASSWORD was accepted")
	}
	t.Setenv("FNB_PASSWORD", "")

	// Half-configured is a startup error.
	t.Setenv("FNB_PASSWORD_FILE", "")
	if _, err := Load(); err == nil {
		t.Error("a username without a password was accepted")
	}
	t.Setenv("FNB_PASSWORD_FILE", secret)
	t.Setenv("FETCH_AT", "6am")
	if _, err := Load(); err == nil {
		t.Error("FETCH_AT=6am was accepted")
	}
}

func TestBackup(t *testing.T) {
	t.Setenv("DB_PATH", "/data/budget.db")
	c, err := Load()
	if err != nil || c.BackupDir != "/data/backups" || c.BackupKeep != 14 {
		t.Fatalf("defaults: %q %d %v", c.BackupDir, c.BackupKeep, err)
	}
	for _, bad := range []string{"-1", "two weeks"} {
		t.Setenv("BACKUP_KEEP", bad)
		if _, err := Load(); err == nil {
			t.Errorf("BACKUP_KEEP=%s was accepted", bad)
		}
	}
}
