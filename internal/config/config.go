// Package config reads the environment into one Config. Nothing else in the
// program reads environment variables.
package config

import (
	"errors"
	"log"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/17xande-dev/env"
	"github.com/17xande-dev/ratelimit/clientip"
)

type Config struct {
	Port   string
	DBPath string

	// CookieSecure marks the session cookie Secure. True by default; set false
	// only for plain-http local development. It doubles as the "is this https"
	// signal for the CSRF origin check, because behind a TLS-terminating proxy
	// the connection reaching us is plain http while the browser's is not.
	CookieSecure bool

	// PublicOrigin is the origin browsers reach the app at (PUBLIC_URL reduced to
	// lower-case scheme://host[:port]). The CSRF check compares a form post's
	// Origin with it exactly, so it must be what the address bar shows. Required
	// when cookies are Secure; plain-http development defaults to
	// http://localhost:PORT.
	PublicOrigin string

	// SessionTTL is how long a sign-in lasts. Two people on their own devices,
	// so the default is long; a password change ends every session regardless.
	SessionTTL time.Duration

	// ClientIPSource says where the address a request came from is read from, for
	// the rate limits: remote (the TCP peer; the default and the safe one, but
	// behind a proxy every client then shares one bucket), forwarded (leftmost
	// X-Forwarded-For) or cloudflare (CF-Connecting-IP). Set it to what is true of
	// the deployment; see clientip.ParseSource.
	ClientIPSource clientip.Source

	// BackupDir receives a daily copy of the database; BackupKeep is how many
	// days are kept there. BackupKeep 0 turns backups off.
	BackupDir  string
	BackupKeep int

	// FNB is the daily fetch's configuration. With no username it is off.
	FNB FNB

	// SetupToken supplies the one-time token that claims the first account, for a
	// deploy that cannot conveniently read the token otherwise printed on first
	// boot. Empty -- the normal case -- means one is generated and logged.
	SetupToken env.Secret
}

// FNB configures the automated fetch.
type FNB struct {
	Username string
	// Password is read from the file FNB_PASSWORD_FILE names (a docker secret),
	// never from a plain environment variable: those end up in `docker inspect`,
	// in process listings and in crash dumps.
	Password env.Secret
	// Profile is the exact name of the profile to choose when the login is
	// linked to several (FNB's "Linked Profiles" page).
	Profile string
	// ChromeURL is the headless Chrome's DevTools endpoint.
	ChromeURL string
	// Hour and Minute are the daily run time in South Africa (FETCH_AT, HH:MM).
	Hour, Minute int
	// Products are the FNB product codes fetched.
	Products []string
}

// MinSetupTokenLength is the shortest SETUP_TOKEN accepted. The token is all that
// stands between a fresh deployment and whoever reaches it first, so a short one
// is worse than none: whoever set it believes it protects them.
const MinSetupTokenLength = 32

func Load() (Config, error) { return load(os.LookupEnv) }

func load(lookup env.Lookup) (Config, error) {
	plainPassword, _ := lookup("FNB_PASSWORD")
	r := env.New(func(key string) (string, bool) {
		// Never let the generic reader accept a password from the environment.
		if key == "FNB_PASSWORD" {
			return "", false
		}
		value, ok := lookup(key)
		// Only the legacy variable is trimmed, as it always was. The file form is
		// read inside the env module, which strips trailing CR/LF and nothing else,
		// and that rule is kept deliberately so every app using the module agrees on
		// what a secret file contains: a space in a file is part of the token.
		if key == "SETUP_TOKEN" {
			value = strings.TrimSpace(value)
		}
		return value, ok
	})
	c := Config{
		Port:         r.String("PORT", "8080"),
		DBPath:       r.String("DB_PATH", "data/budget.db"),
		SetupToken:   r.Secret("SETUP_TOKEN"),
		CookieSecure: r.Bool("COOKIE_SECURE", true),
		SessionTTL:   r.Duration("SESSION_TTL", 30*24*time.Hour, time.Nanosecond, 0),
	}

	// Refused rather than ignored: the old setting trusted forwarding headers from
	// a CIDR list, and silently dropping it would leave a deployment that set it
	// believing it still had per-client limits.
	if _, ok := lookup("TRUSTED_PROXIES"); ok {
		r.Fail("TRUSTED_PROXIES", "has been replaced by CLIENT_IP_SOURCE "+
			"(remote, forwarded or cloudflare); unset it, and set CLIENT_IP_SOURCE=cloudflare only behind the Cloudflare tunnel")
	}
	src, err := clientip.ParseSource(r.String("CLIENT_IP_SOURCE", "remote"))
	if err != nil {
		r.Fail("CLIENT_IP_SOURCE", "must be remote, forwarded or cloudflare")
	}
	c.ClientIPSource = src

	origin, err := publicOrigin(r.String("PUBLIC_URL", ""), c.CookieSecure, c.Port)
	if err != nil {
		r.Fail("PUBLIC_URL", err.Error())
	}
	c.PublicOrigin = origin

	// Beside the database by default, so the one volume holds both; that guards
	// against a bad write or a mistaken delete, not a lost disk -- see README.
	c.BackupDir = r.String("BACKUP_DIR", filepath.Join(filepath.Dir(c.DBPath), "backups"))
	c.BackupKeep = r.Int("BACKUP_KEEP", 14, 0, math.MaxInt)
	if plainPassword != "" {
		r.Fail("FNB_PASSWORD", "is not read; put the password in a file (a docker secret) and set FNB_PASSWORD_FILE to its path")
	}
	c.FNB = loadFNB(r)
	if err := r.Err(); err != nil {
		return Config{}, err
	}

	if length := len(c.SetupToken.Reveal()); c.SetupToken.IsSet() && length < MinSetupTokenLength {
		// Discarded rather than fatal: a generated token is printed instead, so
		// the deployment is still claimable by whoever can read the log -- the
		// safe direction. Loud, so nobody goes on believing theirs is in force.
		log.Printf("SETUP_TOKEN is %d characters, want at least %d; ignoring it and issuing a "+
			"generated token instead (make one with `openssl rand -base64 32`)",
			length, MinSetupTokenLength)
		c.SetupToken = env.Secret{}
	}
	return c, nil
}

// publicOrigin reduces PUBLIC_URL to the origin browsers send in a form post's
// Origin header: lower-case scheme://host[:port], the scheme's default port
// left out, no path. Anything else (userinfo, a path, a query) is refused rather
// than guessed at: a wrong origin would 403 every form.
func publicOrigin(raw string, secure bool, port string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if secure {
			return "", errors.New("is required while COOKIE_SECURE is true; set it to the address browsers use")
		}
		return "http://localhost:" + port, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("must be a bare HTTP or HTTPS origin")
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	switch {
	case scheme != "http" && scheme != "https", host == "", u.User != nil,
		(u.Path != "" && u.Path != "/"), u.RawQuery != "", u.Fragment != "", u.Opaque != "":
		return "", errors.New("must be a bare HTTP or HTTPS origin")
	case secure && scheme != "https":
		return "", errors.New("must use HTTPS while COOKIE_SECURE is true")
	}
	if p := u.Port(); (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		host = strings.TrimSuffix(host, ":"+p)
	}
	return scheme + "://" + host, nil
}

func loadFNB(r *env.Reader) FNB {
	f := FNB{
		Username:  strings.TrimSpace(r.String("FNB_USERNAME", "")),
		Profile:   strings.TrimSpace(r.String("FNB_PROFILE", "")),
		ChromeURL: r.String("CHROME_URL", "ws://chrome:9222/"),
		Products:  r.List("FNB_PRODUCTS", []string{"DDA", "ZFN"}),
		Password:  r.Secret("FNB_PASSWORD"),
	}
	if (f.Username != "") != (r.String("FNB_PASSWORD_FILE", "") != "") {
		// Half-configured is the case to catch at startup, not at 06:00.
		r.Fail("FNB_USERNAME", "must be set together with FNB_PASSWORD_FILE")
	}
	t, err := time.Parse("15:04", r.String("FETCH_AT", "06:00"))
	if err != nil {
		r.Fail("FETCH_AT", "must be HH:MM")
	}
	f.Hour, f.Minute = t.Hour(), t.Minute()
	return f
}
