// Package db opens the SQLite database and owns its schema.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/17xande-dev/sqlitekit"
	"github.com/17xande-dev/sqlitekit/goosestrict"

	// modernc rather than mattn: it is pure Go, so the binary builds with
	// CGO_ENABLED=0 and ships on distroless/static with no libc and no shell.
	// The price is a large machine-translated dependency; see README.
	_ "modernc.org/sqlite"
)

// Options are the SQLite settings the app asks sqlitekit for. Nothing here needs
// secure_delete: the data is financial but a deleted row lingering in a free page
// of a file only the app's user can read is no worse than the live rows.
var Options = sqlitekit.Options{}

// checkSettings is a variable only so a test can prove Open runs it.
var checkSettings = sqlitekit.Check

// The schema is goose migrations under migrations/, embedded. Every table is
// STRICT: SQLite otherwise applies "type affinity" and will happily store the
// string "banana" in an INTEGER column. Every column is therefore TEXT or
// INTEGER. Timestamps are RFC3339 TEXT in UTC; SQLite has no datetime type.
//
// STRICT cannot be retrofitted: CREATE TABLE IF NOT EXISTS ... STRICT silently does
// nothing to a table that already exists, and reports success. db_test.go therefore
// asserts against sqlite_master rather than trusting the DDL.
//
// Schema changes are new numbered migration files, never an edit to an applied
// one and never a startup ALTER: an ALTER against a STRICT table can only
// half-migrate (new column, old table definition), and the database would diverge
// silently from the migration files.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// baselineFile is the schema as it stood when the app moved from CREATE TABLE IF
// NOT EXISTS to goose. A database that predates goose is adopted at this version,
// once, and only after it is verified to match it.
const baselineFile = "0001_baseline.sql"

// versionTable is goose's version table. Its absence on a database that has tables
// marks one that goose has never managed.
const versionTable = "goose_db_version"

// requiredColumns are columns added to a table after it first shipped, from when
// the schema was one CREATE TABLE IF NOT EXISTS script. A database without them
// is refused with a message that says what to do, before the general comparison
// against the baseline would name the same column less helpfully.
var requiredColumns = map[string][]string{
	"transactions": {"category_id", "category_source"},
	"accounts":     {"fetch"},
}

// Open opens the database at path (creating it if needed) and brings its schema up
// to date: a new database is migrated from nothing, one made before goose is
// verified against the baseline and adopted, and one newer than this binary is
// refused.
func Open(path string) (*sql.DB, error) {
	dsn, err := sqlitekit.DSN(path, Options)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Before anything else: a driver that ignored a setting (foreign keys, WAL,
	// busy timeout) would otherwise run silently without it.
	if err := checkSettings(context.Background(), d, Options); err != nil {
		d.Close()
		return nil, fmt.Errorf("sqlite settings not in effect on %s: %w", path, err)
	}
	files, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		d.Close()
		return nil, err // a constant, embedded path
	}
	if err := migrate(context.Background(), d, files); err != nil {
		d.Close()
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	return d, nil
}

// migrate applies the pending migrations in files. A database that has tables but
// no goose version table was made by the old CREATE TABLE IF NOT EXISTS script:
// it is adopted at version 1, but only once it provably holds the baseline's
// schema, because adopting tells goose migration 1 is done and goose never looks
// again. goosestrict.NewProvider refuses a database newer than files.
func migrate(ctx context.Context, d *sql.DB, files fs.FS) error {
	legacy, err := hasTablesButNoVersionTable(ctx, d)
	if err != nil {
		return err
	}
	if legacy {
		if err := verifyBaseline(ctx, d, files); err != nil {
			return err
		}
		if err := goosestrict.Adopt(ctx, d, 1); err != nil {
			return fmt.Errorf("adopt at the baseline: %w", err)
		}
	}
	p, err := goosestrict.NewProvider(d, files)
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func hasTablesButNoVersionTable(ctx context.Context, d *sql.DB) (bool, error) {
	var hasVersion, tables int
	err := d.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE name = ?),
		count(*) FILTER (WHERE name NOT LIKE 'sqlite_%')
		FROM sqlite_master WHERE type = 'table'`, versionTable).Scan(&hasVersion, &tables)
	if err != nil {
		return false, fmt.Errorf("inspect database: %w", err)
	}
	return hasVersion == 0 && tables > 0, nil
}

// column is what the baseline promises about one column: its declared type,
// whether it is NOT NULL, and its primary-key position.
type column struct {
	typ     string
	notNull bool
	pk      int
}

// verifyBaseline refuses a database whose tables are not the baseline's. It builds
// the baseline in a throwaway in-memory database and requires every table and
// column there to exist in the live one with the same type, NOT NULL and primary
// key. Extra tables or columns in the live database are not its business.
func verifyBaseline(ctx context.Context, live *sql.DB, files fs.FS) error {
	for _, table := range sortedKeys(requiredColumns) {
		for _, col := range requiredColumns[table] {
			var n int
			if err := live.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, col).Scan(&n); err != nil {
				return fmt.Errorf("check schema: %w", err)
			}
			if n == 0 {
				return fmt.Errorf("the database predates column %s.%s and cannot be migrated in place: "+
					"recreate it with `make recreate-db` and import the FNB exports again", table, col)
			}
		}
	}

	baseline, err := fs.ReadFile(files, baselineFile)
	if err != nil {
		return err
	}
	ref, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer ref.Close()
	ref.SetMaxOpenConns(1) // every :memory: connection is its own database
	if _, err := ref.ExecContext(ctx, string(baseline)); err != nil {
		return fmt.Errorf("apply the baseline to a scratch database: %w", err)
	}
	want, err := columnsByTable(ctx, ref)
	if err != nil {
		return err
	}
	got, err := columnsByTable(ctx, live)
	if err != nil {
		return err
	}
	strict, err := strictTables(ctx, live)
	if err != nil {
		return err
	}
	for _, table := range sortedKeys(want) {
		have, ok := got[table]
		if !ok {
			return mismatch("table %s is missing", table)
		}
		// STRICT cannot be retrofitted: the baseline's CREATE TABLE IF NOT EXISTS
		// ... STRICT did nothing to a table that already existed, so a live table
		// can have every column right and still accept "banana" in an INTEGER.
		// Adopting it would pin that for ever, so it is refused, not rebuilt.
		if !strict[table] {
			return mismatch("table %s is not STRICT, and STRICT cannot be retrofitted in place: "+
				"it needs a table rebuild (create, copy, drop, rename) done by hand", table)
		}
		for _, name := range sortedKeys(want[table]) {
			w := want[table][name]
			h, ok := have[name]
			switch {
			case !ok:
				return mismatch("column %s.%s is missing", table, name)
			case !strings.EqualFold(h.typ, w.typ):
				return mismatch("column %s.%s has type %s, want %s", table, name, h.typ, w.typ)
			case h.notNull != w.notNull:
				return mismatch("column %s.%s has NOT NULL = %t, want %t", table, name, h.notNull, w.notNull)
			case h.pk != w.pk:
				return mismatch("column %s.%s has primary key position %d, want %d", table, name, h.pk, w.pk)
			}
		}
	}
	return nil
}

func mismatch(format string, args ...any) error {
	return errors.New("the database does not match the baseline schema, so it is not adopted: " +
		fmt.Sprintf(format, args...) + ". Restore a database that matches, or recreate it with `make recreate-db`")
}

// strictTables reports which tables of d are STRICT, from pragma_table_list.
func strictTables(ctx context.Context, d *sql.DB) (map[string]bool, error) {
	rows, err := d.QueryContext(ctx, `SELECT name, strict FROM pragma_table_list WHERE schema = 'main'`)
	if err != nil {
		return nil, fmt.Errorf("read table list: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		var strict int
		if err := rows.Scan(&name, &strict); err != nil {
			return nil, err
		}
		out[name] = strict != 0
	}
	return out, rows.Err()
}

func columnsByTable(ctx context.Context, d *sql.DB) (map[string]map[string]column, error) {
	rows, err := d.QueryContext(ctx, `SELECT m.name, c.name, c.type, c."notnull", c.pk
		FROM sqlite_master m, pragma_table_info(m.name) c
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]column{}
	for rows.Next() {
		var table, name, typ string
		var c column
		var notNull int
		if err := rows.Scan(&table, &name, &typ, &notNull, &c.pk); err != nil {
			return nil, err
		}
		c.typ, c.notNull = typ, notNull != 0
		if out[table] == nil {
			out[table] = map[string]column{}
		}
		out[table][name] = c
	}
	return out, rows.Err()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
