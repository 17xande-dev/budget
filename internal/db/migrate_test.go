package db

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/17xande-dev/sqlitekit/goosestrict"
)

// oldDatabase builds a database exactly as the code before goose did: open it with
// plain settings, apply the old CREATE TABLE IF NOT EXISTS script, no version
// table. tweak edits the script first, to make a database that has drifted.
func oldDatabase(t *testing.T, tweak func(string) string) string {
	t.Helper()
	script, err := os.ReadFile("testdata/old_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	ddl := string(script)
	if tweak != nil {
		ddl = tweak(ddl)
	}
	path := filepath.Join(t.TempDir(), "old.db")
	d, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(ddl); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (email, name, password_hash, created_at) VALUES ('a@example.com', 'A', 'h', '2026-01-01T00:00:00Z')`,
		`INSERT INTO accounts (ref, name, kind, created_at) VALUES ('x1', 'Cheque', 'cheque', '2026-01-01T00:00:00Z')`,
		`INSERT INTO imports (source, filename, account_id, created_at) VALUES ('upload', 'a.ofx', 1, '2026-01-01T00:00:00Z')`,
		`INSERT INTO transactions (account_id, posted_on, amount_cents, description, import_id, dedup_key, created_at)
		 VALUES (1, '2026-01-02', -1234, 'COFFEE', 1, 'k1', '2026-01-02T00:00:00Z')`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return path
}

func count(t *testing.T, d *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The migration files carry the baseline; the fixture is the script the old code
// ran. They must stay the same, or "adopt at 1" stops meaning "the schema the old
// code made". Later changes are new files, never an edit to 0001.
func TestBaselineIsTheOldSchema(t *testing.T) {
	old, err := os.ReadFile("testdata/old_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	got, err := migrationsFS.ReadFile("migrations/" + baselineFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "-- +goose Up\n"+string(old) {
		t.Error("0001_baseline.sql differs from the schema the old code applied")
	}
}

// A database the old code made, with rows in it, is adopted: nothing is lost,
// goose records version 1, and a later migration still applies.
func TestOldDatabaseIsAdopted(t *testing.T) {
	path := oldDatabase(t, nil)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if n := count(t, d, "transactions"); n != 1 {
		t.Errorf("transactions: %d rows, want 1", n)
	}
	var desc string
	var cents int
	if err := d.QueryRow(`SELECT description, amount_cents FROM transactions`).Scan(&desc, &cents); err != nil || desc != "COFFEE" || cents != -1234 {
		t.Errorf("row after adoption: %q %d %v", desc, cents, err)
	}

	// Reopening an adopted database is a no-op: it is no longer "legacy".
	d2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d2.Close()

	files := withLaterMigration(t)
	p, err := goosestrict.NewProvider(d, files)
	if err != nil {
		t.Fatal(err)
	}
	status, err := p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 2 || status[0].State != "applied" || status[1].State != "pending" {
		t.Fatalf("status after adoption: %+v, want 0001 applied and 0002 pending", status)
	}
	if err := migrate(context.Background(), d, files); err != nil {
		t.Fatal(err)
	}
	if n := count(t, d, "later"); n != 0 {
		t.Errorf("later table has %d rows", n)
	}
	if n := count(t, d, "transactions"); n != 1 {
		t.Errorf("transactions after a later migration: %d rows", n)
	}
}

func withLaterMigration(t *testing.T) fs.FS {
	t.Helper()
	base, err := migrationsFS.ReadFile("migrations/" + baselineFile)
	if err != nil {
		t.Fatal(err)
	}
	return fstest.MapFS{
		baselineFile:     {Data: base},
		"0002_later.sql": {Data: []byte("-- +goose Up\nCREATE TABLE later (id INTEGER PRIMARY KEY) STRICT;\n")},
	}
}

// Without Adopt, goosestrict refuses the old database: this is the failure the
// adoption exists to prevent, and what a skipped Adopt would look like.
func TestOldDatabaseNeedsAdopt(t *testing.T) {
	path := oldDatabase(t, nil)
	d, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	_, err = goosestrict.NewProvider(d, withLaterMigration(t))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "adopt") {
		t.Fatalf("NewProvider on an unadopted database: %v, want a refusal that says to adopt", err)
	}
}

func TestFreshDatabaseMigratesFromZero(t *testing.T) {
	d := openTemp(t)
	p, err := goosestrict.NewProvider(d, withLaterMigration(t))
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.GetDBVersion(context.Background())
	if err != nil || v != 1 {
		t.Fatalf("version of a fresh database = %d, %v; want 1", v, err)
	}
	if n := count(t, d, "accounts"); n != 0 {
		t.Errorf("fresh accounts: %d", n)
	}
	if err := migrate(context.Background(), d, withLaterMigration(t)); err != nil {
		t.Fatal(err)
	}
	if v, _ := p.GetDBVersion(context.Background()); v != 2 {
		t.Errorf("version after a later migration = %d, want 2", v)
	}
}

// A database written by a newer build must not be opened by an older one.
func TestNewerDatabaseRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(context.Background(), d, withLaterMigration(t)); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("a database at version 2 was opened by a binary that knows version 1")
	}
}

// Adopting at 1 tells goose migration 1 is done; if the schema is not the
// baseline's that is a silent lie, so every deviation is refused by name.
func TestAdoptionRefusesASchemaMismatch(t *testing.T) {
	cases := []struct {
		name  string
		tweak func(string) string
		want  string
	}{
		{"index on other columns", func(s string) string {
			return strings.Replace(s, "ON sessions(user_id)", "ON sessions(token_hash)", 1)
		}, "index idx_sessions_user is on sessions(token_hash)"},
		{"index not unique", func(s string) string {
			return strings.Replace(s, "CREATE INDEX IF NOT EXISTS idx_transactions_date", "CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_date", 1)
		}, "index idx_transactions_date is on transactions(posted_on) unique=true"},
		{"unique constraint dropped", func(s string) string {
			return strings.Replace(s, "	token_hash   TEXT NOT NULL UNIQUE,", "	token_hash   TEXT NOT NULL,", 1)
		}, "table api_tokens lacks the unique constraint on (token_hash)"},
		{"missing column", func(s string) string { return strings.Replace(s, "	token_name TEXT NOT NULL DEFAULT '',\n", "", 1) }, "audit_log.token_name is missing"},
		{"wrong type", func(s string) string {
			// categories has no seeded rows, so the INTEGER column accepts the fixture.
			return strings.Replace(s, "name       TEXT NOT NULL UNIQUE COLLATE NOCASE", "name       INTEGER NOT NULL UNIQUE COLLATE NOCASE", 1)
		}, "categories.name has type INTEGER, want TEXT"},
		{"not null dropped", func(s string) string {
			return strings.Replace(s, "	dedup_key     TEXT NOT NULL UNIQUE,", "	dedup_key     TEXT UNIQUE,", 1)
		}, "transactions.dedup_key has NOT NULL = false"},
		{"primary key dropped", func(s string) string {
			return strings.Replace(s, "	token_hash TEXT PRIMARY KEY,", "	token_hash TEXT NOT NULL,", 1)
		}, "sessions.token_hash has primary key position 0"},
		{"not strict", func(s string) string {
			// rules has only INTEGER and TEXT columns with explicit NOT NULL, so
			// dropping STRICT changes nothing else the column comparison could see.
			return strings.Replace(s, ") STRICT;\n\n-- How much a category may take", ");\n\n-- How much a category may take", 1)
		}, "table rules is not STRICT"},
		{"required column", func(s string) string {
			return strings.Replace(s, "	fetch      INTEGER NOT NULL DEFAULT 1 CHECK (fetch IN (0, 1)),\n", "", 1)
		}, "accounts.fetch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := oldDatabase(t, c.tweak)
			_, err := Open(path)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Open = %v, want an error containing %q", err, c.want)
			}
			// Refused means untouched: no version table was written.
			d, _ := sql.Open("sqlite", "file:"+path)
			defer d.Close()
			var n int
			d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = ?`, versionTable).Scan(&n)
			if n != 0 {
				t.Error("a refused database got a version table")
			}
		})
	}
}

func tableExists(t *testing.T, d *sql.DB, kind, name string) bool {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?`, kind, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// An image from before a table or index existed booted fine on the old binary, which
// created whatever was missing on every start. Adopting must do the same, or the
// first deploy of this version would refuse a database the last one accepted.
func TestLegacyDatabaseMissingATableIsCompleted(t *testing.T) {
	path := oldDatabase(t, func(s string) string {
		return strings.Replace(s, "CREATE TABLE IF NOT EXISTS fetch_runs", "CREATE TABLE IF NOT EXISTS unrelated_runs", 1)
	})
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !tableExists(t, d, "table", "fetch_runs") {
		t.Fatal("the missing table was not created")
	}
	strict, err := strictTables(t.Context(), d)
	if err != nil || !strict["fetch_runs"] {
		t.Errorf("fetch_runs strict = %v, %v; want a STRICT table", strict["fetch_runs"], err)
	}
	if n := count(t, d, "transactions"); n != 1 {
		t.Errorf("transactions: %d rows, want 1", n)
	}
	p, err := goosestrict.NewProvider(d, withLaterMigration(t))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := p.GetDBVersion(t.Context()); err != nil || v != 1 {
		t.Errorf("adopted at %d, %v; want 1", v, err)
	}
}

func TestLegacyDatabaseMissingAnIndexIsCompleted(t *testing.T) {
	path := oldDatabase(t, func(s string) string {
		return strings.Replace(s, "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);", "", 1)
	})
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !tableExists(t, d, "index", "idx_sessions_user") {
		t.Fatal("the missing index was not created")
	}
}

// The refusal must not claim the file is untouched (it is WAL now and may have
// gained tables), and must say how to get an adoptable database.
func TestRefusalSaysWhatIsWrongAndHowToFixIt(t *testing.T) {
	path := oldDatabase(t, func(s string) string {
		return strings.Replace(s, "name       TEXT NOT NULL UNIQUE COLLATE NOCASE", "name       INTEGER NOT NULL UNIQUE COLLATE NOCASE", 1)
	})
	_, err := Open(path)
	if err == nil {
		t.Fatal("a wrongly typed column was adopted")
	}
	for _, want := range []string{"categories.name has type INTEGER", "previous image", "restore a backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "untouched") || strings.Contains(err.Error(), "unchanged") {
		t.Errorf("refusal claims the file was not changed: %q", err)
	}
}
