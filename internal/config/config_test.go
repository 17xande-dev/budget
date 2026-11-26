package config

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	for _, invalid := range []string{"ture", "1", "TRUE"} {
		t.Run(invalid, func(t *testing.T) {
			t.Setenv("COOKIE_SECURE", invalid)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "COOKIE_SECURE") {
				t.Fatal("expected a refusal naming COOKIE_SECURE")
			}
		})
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
	if c.SetupToken.IsSet() {
		t.Error("a short SETUP_TOKEN was kept")
	}
	t.Setenv("SETUP_TOKEN", "  "+strings.Repeat("x", MinSetupTokenLength)+"\n")
	c, _ = Load()
	if c.SetupToken.Reveal() != strings.Repeat("x", MinSetupTokenLength) {
		t.Error("a long SETUP_TOKEN was not kept trimmed")
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
	// Present-but-empty counts as set: an empty export of the old name still
	// means the deployment has not read the replacement notice.
	for _, value := range []string{"172.16.0.0/12", ""} {
		t.Run(fmt.Sprintf("value %q", value), func(t *testing.T) {
			t.Setenv("TRUSTED_PROXIES", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES:") {
				t.Errorf("TRUSTED_PROXIES=%q was accepted: %v", value, err)
			}
		})
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
	if c.FNB.Password.Reveal() != "hunter2-not-really" || c.FNB.Hour != 5 || c.FNB.Minute != 30 || len(c.FNB.Products) != 2 {
		t.Errorf("fnb config: %+v", c.FNB)
	}

	// A password in a plain environment variable is refused, not used.
	t.Setenv("FNB_PASSWORD", "plain")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "FNB_PASSWORD:") {
		t.Error("FNB_PASSWORD was accepted")
	}
	t.Setenv("FNB_PASSWORD_FILE", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "FNB_PASSWORD:") {
		t.Error("FNB_PASSWORD without a file was accepted")
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

// The loader hides FNB_PASSWORD from the generic secret reader as well as
// refusing it. Without the wrapper, a plain password beside a password file
// would add a second, misleading "cannot be set together" complaint to the
// refusal, and the plain variable would look like a recognised setting.
func TestPlainPasswordIsHiddenFromSecretReader(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "fnb_password")
	if err := os.WriteFile(secret, []byte("not-really\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FNB_USERNAME", "someone")
	t.Setenv("FNB_PASSWORD_FILE", secret)
	t.Setenv("FNB_PASSWORD", "plain")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "FNB_PASSWORD: is not read") {
		t.Fatalf("plain password beside a file was not refused: %v", err)
	}
	if strings.Contains(err.Error(), "cannot be set together") {
		t.Errorf("the plain variable reached the secret reader: %v", err)
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

// Preserve password bytes other than trailing CR/LF and don't echo bad paths:
// operators sometimes paste the password itself into the path variable.
func TestFNBPasswordFileStripsOnlyTrailingCRLFAndRefusesBadFiles(t *testing.T) {
	root := t.TempDir()
	write := func(name string, content []byte) string {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	load := func(t *testing.T, user, path string) (Config, error) {
		t.Setenv("FNB_USERNAME", user)
		t.Setenv("FNB_PASSWORD_FILE", path)
		return Load()
	}
	for _, tc := range []struct{ name, content, want string }{
		{"lf", "pw\n", "pw"},
		{"crlf", "pw\r\n", "pw"},
		{"double_lf", "pw\n\n", "pw"},
		{"double_crlf", "pw\r\n\r\n", "pw"},
		{"lf_then_cr", "pw\n\r", "pw"},
		{"lone_cr", "pw\r", "pw"},
		{"trailing_spaces_kept", "pw  \r\n", "pw  "},
		{"other_whitespace_kept", " pw \t\n", " pw \t"},
		{"leading_newline_kept", "\npw\n", "\npw"},
		{"inner_newline_kept", "p\nw\n", "p\nw"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, "someone", write("ok-"+tc.name, []byte(tc.content)))
			if err != nil {
				t.Fatal(err)
			}
			if c.FNB.Password.Reveal() != tc.want {
				t.Error("FNB password did not match the expected bytes")
			}
		})
	}

	loadFIFO := func(user string, path string) error {
		t.Helper()
		// A blocking open or read should fail this test, not hang the package.
		t.Setenv("FNB_USERNAME", user)
		t.Setenv("FNB_PASSWORD_FILE", path)
		done := make(chan error, 1)
		go func() {
			_, err := Load()
			done <- err
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatalf("Load blocked on the FNB password FIFO for 5 seconds (user %q)", user)
			return nil
		}
	}
	fifo := filepath.Join(root, "fifo-secret")
	fifoErr := syscall.Mkfifo(fifo, 0o600)
	cases := []struct{ name, path string }{
		{"missing", filepath.Join(root, "absent-secret")},
		{"empty", write("empty-secret", nil)},
		{"newline only", write("newline-secret", []byte("\r\n"))},
		{"repeated newlines only", write("repeated-newlines-secret", []byte("\r\n\r\n"))},
		{"70 KiB", write("big-secret", bytes.Repeat([]byte("a"), 70<<10))},
		{"directory", root},
	}
	if fifoErr == nil {
		cases = append(cases, struct{ name, path string }{"fifo", fifo})
	}
	for _, tc := range cases {
		// A username-less deployment must refuse too: an empty file used to
		// leave the fetch silently off.
		for _, user := range []string{"someone", ""} {
			var err error
			if tc.path == fifo {
				err = loadFIFO(user, tc.path)
			} else {
				_, err = load(t, user, tc.path)
			}
			if err == nil {
				t.Errorf("%s (user %q): accepted", tc.name, user)
				continue
			}
			if !strings.Contains(err.Error(), "FNB_PASSWORD_FILE") || strings.Contains(err.Error(), tc.path) || strings.Contains(err.Error(), filepath.Base(tc.path)) {
				t.Errorf("%s: error must name the key and not the path: %v", tc.name, err)
			}
		}
	}

	// A FIFO with a writer reads fine unless its type is checked.
	if fifoErr == nil {
		go func() {
			if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
				w.WriteString("looks-valid\n")
				w.Close()
			}
		}()
		if err := loadFIFO("someone", fifo); err == nil || !strings.Contains(err.Error(), "must name a regular file") {
			t.Errorf("fifo with a writer: %v", err)
		}
	}
}

func TestFNBPasswordFileSizeLimit(t *testing.T) {
	t.Setenv("FNB_USERNAME", "someone")
	for _, tc := range []struct {
		name string
		size int
		want string
	}{
		{name: "exactly 64 KiB", size: 64 << 10},
		{name: "64 KiB plus one", size: 64<<10 + 1, want: "FNB_PASSWORD_FILE: secret file exceeds 64 KiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			password := strings.Repeat("a", tc.size)
			if err := os.WriteFile(path, []byte(password), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("FNB_PASSWORD_FILE", path)
			c, err := Load()
			if tc.want != "" {
				if err == nil || err.Error() != tc.want {
					t.Fatalf("want an error rejecting the oversized file, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.FNB.Password.Reveal() != password {
				t.Error("password bytes changed at the size limit")
			}
		})
	}
}
