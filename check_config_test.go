package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/17xande-dev/budget/internal/config"
)

// The child the tests below start, so -check-config runs through the real run()
// (flag parsing, config.Load, exit status) rather than a copy of it.
func TestCheckConfigHelperProcess(t *testing.T) {
	if os.Getenv("BUDGET_CHECK_CONFIG_CHILD") != "1" {
		t.Skip("only runs as the child of the check-config tests")
	}
	os.Exit(run(strings.Fields(os.Getenv("BUDGET_CHECK_CONFIG_ARGS")), os.Stdout, os.Stderr))
}

func runCheck(t *testing.T, args string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCheckConfigHelperProcess$")
	cmd.Env = append(os.Environ(),
		"BUDGET_CHECK_CONFIG_CHILD=1", "BUDGET_CHECK_CONFIG_ARGS="+args,
		"COOKIE_SECURE=", "PUBLIC_URL=", "SESSION_TTL=", "FNB_USERNAME=", "FNB_PASSWORD_FILE=", "FETCH_AT=",
		"CLIENT_IP_SOURCE=", "SETUP_TOKEN=", "SETUP_TOKEN_FILE=", "BACKUP_KEEP=", "BACKUP_DIR=", "DB_PATH=",
	)
	cmd.Env = append(cmd.Env, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), code
}

func validEnv(t *testing.T) (dir string, env []string) {
	dir = t.TempDir()
	return dir, []string{"DB_PATH=" + filepath.Join(dir, "budget.db"), "PUBLIC_URL=https://budget.example"}
}

// A database file, its -wal/-shm or a lock would all show up as entries.
func assertUntouched(t *testing.T, dir string) {
	t.Helper()
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the database directory was touched: %v, %v", entries, err)
	}
}

func TestCheckConfigOK(t *testing.T) {
	dir, env := validEnv(t)
	out, code := runCheck(t, "-check-config", env...)
	if code != 0 || !strings.Contains(out, "config: ok") {
		t.Fatalf("exit %d, output %q; want 0 and config: ok", code, out)
	}
	assertUntouched(t, dir)
}

func TestCheckConfigReportsAllProblems(t *testing.T) {
	const secret = "zz-secret-value-123"
	dir, env := validEnv(t)
	secretFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCheck(t, "-check-config", append(env,
		"FETCH_AT=zz-marker-time", "CLIENT_IP_SOURCE=zz-marker-source", "FNB_PASSWORD_FILE="+secretFile)...)
	if code != 1 {
		t.Fatalf("exit %d, output %q; want 1", code, out)
	}
	for _, name := range []string{"FETCH_AT", "CLIENT_IP_SOURCE", "FNB_USERNAME"} {
		if !strings.Contains(out, name) {
			t.Errorf("output does not name %s: %q", name, out)
		}
	}
	for _, leak := range []string{secret, "zz-marker"} {
		if strings.Contains(out, leak) {
			t.Errorf("output contains a configured value %q: %q", leak, out)
		}
	}
	assertUntouched(t, dir)
}

// A subcommand's arguments are not flags, and the check wins over them.
func TestCheckConfigBeatsSubcommands(t *testing.T) {
	dir, env := validEnv(t)
	out, code := runCheck(t, "-check-config reset-password nobody@example.com", env...)
	if code != 0 || !strings.Contains(out, "config: ok") {
		t.Fatalf("exit %d, output %q", code, out)
	}
	assertUntouched(t, dir)
}

// What the server refuses after config.Load, -check-config refuses too: serve
// runs the same validateConfig, before opening the database.
func TestCheckConfigMatchesServer(t *testing.T) {
	dir := t.TempDir()
	// Load never produces this pair (it refuses a non-HTTPS origin while cookies
	// are Secure), but the CSRF check inside handler.New does.
	cfg := config.Config{DBPath: filepath.Join(dir, "budget.db"), CookieSecure: true, PublicOrigin: "http://budget.example", SessionTTL: 1}
	checkErr := validateConfig(cfg)
	if checkErr == nil {
		t.Fatal("validateConfig accepted a config the server refuses")
	}
	if serveErr := serve(cfg); serveErr == nil || serveErr.Error() != checkErr.Error() {
		t.Errorf("serve = %v; want %v", serveErr, checkErr)
	}
	assertUntouched(t, dir)
}
