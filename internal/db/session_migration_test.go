package db

import (
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/17xande-dev/sqlitekit/goosestrict"
)

// openPlain opens a database file as the pre-goose code did, with no migration.
func openPlain(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
}

func columnsOf(t *testing.T, d *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := d.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		cols[n] = true
	}
	return cols
}

// A database the previous release made, with rows in every table that holds
// people's data, goes through 0002: sessions survive, last_seen_at is backfilled
// to the migration, a second Open changes nothing, Down returns to the previous
// goose version and schema (which the previous binary accepts), and Up again
// works.
func TestSessionLastSeenMigration(t *testing.T) {
	path := oldDatabase(t, nil) // users, accounts, imports, transactions
	legacy, err := openPlain(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES ('s1', 1, '2026-11-01T08:00:00Z', '2099-01-01T00:00:00Z')`,
		`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES ('s2', 1, '2026-11-02T08:00:00Z', '2099-01-01T00:00:00Z')`,
		`INSERT INTO api_tokens (user_id, name, token_hash, created_at, expires_at) VALUES (1, 'laptop', 't1', '2026-11-01T08:00:00Z', '2099-01-01T00:00:00Z')`,
	} {
		if _, err := legacy.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	legacy.Close()

	before := time.Now().Add(-2 * time.Second)
	d, err := Open(path) // adopts at 1, then applies 0002
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	after := time.Now().Add(2 * time.Second)

	if n := count(t, d, "sessions"); n != 2 {
		t.Fatalf("sessions after the migration: %d, want 2", n)
	}
	seen := map[string]string{}
	rows, err := d.Query(`SELECT token_hash, last_seen_at FROM sessions`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var h, ls string
		if err := rows.Scan(&h, &ls); err != nil {
			t.Fatal(err)
		}
		at, err := time.Parse(time.RFC3339, ls)
		if err != nil || at.Before(before) || at.After(after) {
			t.Errorf("session %s last_seen_at = %q (%v), want the migration time", h, ls, err)
		}
		seen[h] = ls
	}
	rows.Close()
	for table, want := range map[string]int{"users": 1, "accounts": 1, "imports": 1, "transactions": 1, "api_tokens": 1} {
		if n := count(t, d, table); n != want {
			t.Errorf("%s after the migration: %d rows, want %d", table, n, want)
		}
	}

	// A second Open is a no-op: same version rows, same values.
	d2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var versions int
	d2.QueryRow(`SELECT count(*) FROM goose_db_version`).Scan(&versions)
	for h, ls := range seen {
		var got string
		d2.QueryRow(`SELECT last_seen_at FROM sessions WHERE token_hash = ?`, h).Scan(&got)
		if got != ls {
			t.Errorf("second Open rewrote %s last_seen_at: %q -> %q", h, ls, got)
		}
	}
	d2.Close()
	if versions != 3 { // version 0, the baseline, 0002
		t.Errorf("goose_db_version rows after a second Open = %d, want 3", versions)
	}

	// The previous binary knows only the baseline: it refuses this database...
	files, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	baselineOnly := func() fs.FS {
		b, _ := migrationsFS.ReadFile("migrations/" + baselineFile)
		return fstest.MapFS{baselineFile: {Data: b}}
	}()
	if _, err := goosestrict.NewProvider(d, baselineOnly); err == nil {
		t.Fatal("the previous binary opened a database with 0002 applied")
	}
	// ...until Down has run.
	p, err := goosestrict.NewProvider(d, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(t.Context(), 1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if v, err := p.GetDBVersion(t.Context()); err != nil || v != 1 {
		t.Fatalf("version after Down = %d, %v; want 1", v, err)
	}
	if cols := columnsOf(t, d, "sessions"); cols["last_seen_at"] || len(cols) != 4 {
		t.Errorf("sessions columns after Down: %v, want the baseline's four", cols)
	}
	if n := count(t, d, "sessions"); n != 2 {
		t.Errorf("sessions after Down: %d, want 2", n)
	}
	if _, err := goosestrict.NewProvider(d, baselineOnly); err != nil {
		t.Errorf("the previous binary refuses the rolled-back database: %v", err)
	}
	// Up again re-applies it (backfilled to that later moment).
	if _, err := p.Up(t.Context()); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if cols := columnsOf(t, d, "sessions"); !cols["last_seen_at"] {
		t.Error("Up after Down did not add the column")
	}
}
