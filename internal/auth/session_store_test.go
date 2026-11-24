package auth_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/17xande-dev/budget/internal/auth"
	"github.com/17xande-dev/budget/internal/db"
	"github.com/17xande-dev/websec/session"
	"github.com/17xande-dev/websec/session/sessiontest"
)

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// The websec conformance suite against the real store and the real lifetime
// (7 days idle, 30 days absolute). Time moves by backdating rows; the store is
// asked at the real time.
func TestSessionStoreConformance(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "suite.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s := auth.NewStore(d)
	pw := hash(t, "correct horse battery")
	var seq atomic.Int64
	ids := map[string]int64{}
	count := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := d.QueryRow(`SELECT count(*) FROM sessions`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// The stored form: sha256 of the token, hex. Derived here on purpose, so the
	// suite does not trust the store's own helper.
	hashOf := func(token string) string { sum := sha256.Sum256([]byte(token)); return hex.EncodeToString(sum[:]) }

	sessiontest.Run(t, sessiontest.Harness{
		Lifetime: s.Life,
		NewUser: func(t *testing.T) string {
			t.Helper()
			email := fmt.Sprintf("suite-%d@example.com", seq.Add(1))
			u, err := s.CreateUser(email, "Suite", pw, false, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			ids[email] = u.ID
			return email
		},
		Create: func(t *testing.T, email string) string {
			t.Helper()
			token, err := s.IssueSession(ids[email], time.Now(), s.Life.Absolute)
			if err != nil {
				t.Fatal(err)
			}
			return token
		},
		Lookup: func(t *testing.T, token string) (string, bool, error) {
			u, ok, err := s.VerifySession(token, time.Now())
			return u.Email, ok, err
		},
		Backdate: func(t *testing.T, token string, created, lastSeen time.Time) {
			t.Helper()
			// expires_at is derived: the absolute end counted from creation.
			res, err := d.Exec(`UPDATE sessions SET created_at = ?, last_seen_at = ?, expires_at = ? WHERE token_hash = ?`,
				rfc3339(created), rfc3339(lastSeen), rfc3339(s.Life.AbsoluteExpiry(created)), hashOf(token))
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				t.Fatalf("backdated %d rows", n)
			}
		},
		LastSeen: func(t *testing.T, token string) time.Time {
			t.Helper()
			var ls string
			if err := d.QueryRow(`SELECT last_seen_at FROM sessions WHERE token_hash = ?`, hashOf(token)).Scan(&ls); err != nil {
				t.Fatal(err)
			}
			at, err := time.Parse(time.RFC3339, ls)
			if err != nil {
				t.Fatal(err)
			}
			return at
		},
		Sweep: func(t *testing.T) int {
			t.Helper()
			n, err := s.DeleteExpiredSessions(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			return int(n)
		},
		Count: count,
		RawRows: func(t *testing.T) []string {
			t.Helper()
			return rawSessionRows(t, d)
		},
		// There are no disabled accounts in this app.
		NotApplicable: map[sessiontest.Case]string{
			sessiontest.CaseDisable: "no disabled accounts",
		},
		// An administrator's way to end someone's sessions is setting their password
		// (the reset-password command, or a new member's temporary one).
		RevokeUser: func(t *testing.T, email string) {
			t.Helper()
			if ok, err := s.SetPassword(ids[email], hash(t, "a whole new passphrase"), true); err != nil || !ok {
				t.Fatal(ok, err)
			}
		},
		// Changing the password ends every session, the current one included.
		ChangePassword: func(t *testing.T, email, current string) string {
			t.Helper()
			if ok, err := s.SetPassword(ids[email], hash(t, "a different passphrase"), false); err != nil || !ok {
				t.Fatal(ok, err)
			}
			return ""
		},
	})
}

func rawSessionRows(t *testing.T, d *sql.DB) []string {
	t.Helper()
	rows, err := d.Query(`SELECT token_hash, user_id, created_at, expires_at, last_seen_at FROM sessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h, c, e, l string
		var id int64
		if err := rows.Scan(&h, &id, &c, &e, &l); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s|%d|%s|%s|%s", h, id, c, e, l))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// SESSION_TTL is the absolute end; the idle limit is a week, or the TTL when that
// is shorter, and the result is always a valid lifetime.
func TestLifetimeFollowsSessionTTL(t *testing.T) {
	for ttl, want := range map[time.Duration]session.Lifetime{
		30 * 24 * time.Hour: {Idle: 7 * 24 * time.Hour, Absolute: 30 * 24 * time.Hour},
		90 * 24 * time.Hour: {Idle: 7 * 24 * time.Hour, Absolute: 90 * 24 * time.Hour},
		24 * time.Hour:      {Idle: 24 * time.Hour, Absolute: 24 * time.Hour},
	} {
		got := auth.Lifetime(ttl)
		if got != want || got.Validate() != nil {
			t.Errorf("Lifetime(%v) = %+v (%v), want %+v", ttl, got, got.Validate(), want)
		}
	}
}

// A session unused for the idle limit ends; the same session used inside it
// does not, and each use renews the idle window (written at most once a minute).
func TestIdleSessionEnds(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateUser("idle@example.com", "I", hash(t, "correct horse battery"), false, t0)
	tok, _ := s.IssueSession(u.ID, t0, 30*24*time.Hour)
	if _, ok, _ := s.VerifySession(tok, t0.Add(6*24*time.Hour)); !ok {
		t.Fatal("a session used within the idle limit ended")
	}
	// That use renewed the window: six more days is still inside it.
	if _, ok, _ := s.VerifySession(tok, t0.Add(12*24*time.Hour)); !ok {
		t.Fatal("use did not renew the idle window")
	}
	if _, ok, _ := s.VerifySession(tok, t0.Add(20*24*time.Hour)); ok {
		t.Fatal("a session unused for more than a week survived")
	}
}
