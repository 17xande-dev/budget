package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/env/envtest"
)

func TestConfigDocumentation(t *testing.T) {
	recorder := envtest.NewRecorder(map[string]string{"PUBLIC_URL": "https://budget.example.com"})
	if _, err := load(recorder.Lookup); err != nil {
		t.Fatal(err)
	}
	read := slices.DeleteFunc(recorder.Keys(), func(key string) bool {
		return key == "TRUSTED_PROXIES" // Refused legacy name.
	})
	documented := slices.DeleteFunc(envtest.EnvExample(t, "../../.env.example"), func(key string) bool {
		return key == "BUDGET_HOST" // Used by Compose for routing and interpolation.
	})
	envtest.Documented(t, ".env.example", read, documented)
}

func TestProductionValues(t *testing.T) {
	t.Run("Kamal", func(t *testing.T) {
		// Image defaults plus config/deploy.yml env.clear.
		settings := map[string]string{
			"DB_PATH":          "/data/budget.db",
			"PORT":             "8080",
			"COOKIE_SECURE":    "true",
			"PUBLIC_URL":       "https://budget.17xande.dev",
			"CLIENT_IP_SOURCE": "cloudflare",
		}
		cfg, err := load(envtest.NewRecorder(settings).Lookup)
		if err != nil || !cfg.CookieSecure {
			t.Fatalf("Kamal configuration: %v", err)
		}
	})
	t.Run("Compose", func(t *testing.T) {
		settings := map[string]string{
			"DB_PATH":           "/data/budget.db",
			"PORT":              "8080",
			"FNB_PASSWORD_FILE": "/run/secrets/fnb_password",
			"CHROME_URL":        "ws://chrome:9222/",
			"PUBLIC_URL":        "${PUBLIC_URL:-https://${BUDGET_HOST}}",
			"FNB_USERNAME":      "compose-fixture",
		}
		path := filepath.Join(t.TempDir(), "fnb_password")
		if err := os.WriteFile(path, []byte("fixture-password\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		recorder := envtest.NewRecorder(settings)
		cfg, err := load(func(key string) (string, bool) {
			value, ok := recorder.Lookup(key)
			// Model the mount and interpolation without running a deployment.
			switch {
			case key == "FNB_PASSWORD_FILE" && value == "/run/secrets/fnb_password":
				return path, ok
			case key == "PUBLIC_URL" && value == "${PUBLIC_URL:-https://${BUDGET_HOST}}":
				return "https://budget.example.com", ok
			}
			return value, ok
		})
		if err != nil || cfg.PublicOrigin != "https://budget.example.com" || !cfg.FNB.Password.IsSet() {
			t.Fatalf("Compose configuration: %v", err)
		}
	})
}

func TestEmptySettingsUseDefaults(t *testing.T) {
	recorder := envtest.NewRecorder(map[string]string{
		"PUBLIC_URL": "https://budget.example.com",
		"PORT":       "", "DB_PATH": "", "COOKIE_SECURE": "", "SESSION_TTL": "",
		"BACKUP_KEEP": "", "CLIENT_IP_SOURCE": "", "FETCH_AT": "", "FNB_PRODUCTS": "",
	})
	cfg, err := load(recorder.Lookup)
	if err != nil || cfg.Port != "8080" || cfg.DBPath != "data/budget.db" || !cfg.CookieSecure ||
		cfg.SessionTTL != 720*time.Hour || cfg.BackupKeep != 14 || cfg.FNB.Hour != 6 ||
		!slices.Equal(cfg.FNB.Products, []string{"DDA", "ZFN"}) {
		t.Fatalf("empty settings did not use defaults: %+v, %v", cfg, err)
	}
}

func TestPortRemainsAString(t *testing.T) {
	// The app passes PORT to net/http, which also accepts service names.
	cfg, err := load(envtest.NewRecorder(map[string]string{
		"COOKIE_SECURE": "false", "PORT": "http-alt",
	}).Lookup)
	if err != nil || cfg.Port != "http-alt" || cfg.PublicOrigin != "http://localhost:http-alt" {
		t.Fatalf("expected PORT to pass through unchanged, got %q and %q: %v", cfg.Port, cfg.PublicOrigin, err)
	}
}

func TestConfigErrorsDoNotEchoValues(t *testing.T) {
	values := map[string]string{
		"PUBLIC_URL":    "https://user:origin-fixture@example.com",
		"COOKIE_SECURE": "cookie-fixture", "SESSION_TTL": "ttl-fixture",
		"CLIENT_IP_SOURCE": "source-fixture", "BACKUP_KEEP": "keep-fixture",
		"FETCH_AT": "time-fixture", "FNB_PASSWORD": "plain-fixture",
	}
	_, err := load(envtest.NewRecorder(values).Lookup)
	if err == nil {
		t.Fatal("invalid settings were accepted")
	}
	for key, value := range values {
		if !strings.Contains(err.Error(), key+":") || strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "origin-fixture") {
			t.Errorf("expected a value-free diagnostic for %s", key)
		}
	}
}

func TestConfigRedactsSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("fnb-redaction-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := load(envtest.NewRecorder(map[string]string{
		"PUBLIC_URL": "https://budget.example.com", "FNB_USERNAME": "someone", "FNB_PASSWORD_FILE": path,
		"SETUP_TOKEN": strings.Repeat("setup-redaction-fixture", 2),
	}).Lookup)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(format, cfg)
		if strings.Contains(out, "redaction-fixture") || strings.Count(out, "[redacted]") != 2 {
			t.Errorf("expected both secrets to be redacted for %s", format)
		}
	}
}
