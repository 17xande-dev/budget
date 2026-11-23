package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/17xande-dev/sqlitekit"
)

// openConcurrently opens path from n goroutines released together and fails the
// test if any Open fails. Without the migration lock, the first connection to a
// fresh file and the adoption of a legacy one race: one opener gets SQLITE_BUSY
// (busy_timeout does not cover the first open or the switch to WAL) or two openers
// both adopt and the second dies on the version table that already exists.
func openConcurrently(t *testing.T, path string, n int) {
	t.Helper()
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, err := Open(path)
			if err == nil {
				d.Close()
			}
			errs[i] = err
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("opener %d: %v", i, err)
		}
	}
}

// requireEachVersionOnce reads goose's table: a version recorded twice means two
// openers both ran the same migration.
func requireEachVersionOnce(t *testing.T, path string, want int) {
	t.Helper()
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var rows, distinct int
	if err := d.QueryRow(`SELECT count(*), count(DISTINCT version_id) FROM goose_db_version`).Scan(&rows, &distinct); err != nil {
		t.Fatal(err)
	}
	if rows != distinct || rows != want {
		t.Errorf("goose_db_version has %d rows, %d distinct versions; want %d, each once", rows, distinct, want)
	}
}

// A lock held by a stuck process must make Open fail, not hang the start for ever.
func TestOpenGivesUpWhenTheMigrationLockStaysHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "held.db")
	release, err := sqlitekit.MigrationLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	old := lockWait
	lockWait = 100 * time.Millisecond
	defer func() { lockWait = old }()

	done := make(chan error, 1)
	go func() {
		d, err := Open(path)
		if err == nil {
			d.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open succeeded while another process held the migration lock")
		}
		for _, want := range []string{"held by another process", path + sqlitekit.MigrationLockSuffix} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Open is still waiting for the migration lock well past its bound")
	}
}

func TestConcurrentOpensOfAFreshDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	openConcurrently(t, path, 8)
	requireEachVersionOnce(t, path, 2) // version 0 and the baseline
}

func TestConcurrentOpensOfALegacyDatabase(t *testing.T) {
	path := oldDatabase(t, nil)
	openConcurrently(t, path, 8)
	requireEachVersionOnce(t, path, 2)
	d, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if n := count(t, d, "transactions"); n != 1 {
		t.Errorf("transactions: %d rows after concurrent adoption, want 1", n)
	}
}
