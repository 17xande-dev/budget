package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/17xande-dev/budget/internal/db"
	"github.com/17xande-dev/sqlitekit"
)

func TestDeployStopTimeoutCoversShutdown(t *testing.T) {
	data, err := os.ReadFile("config/deploy.yml")
	if err != nil {
		t.Fatal(err)
	}
	lines := regexp.MustCompile(`(?m)^stop_timeout:[^\n]*$`).FindAllString(string(data), -1)
	if len(lines) != 1 {
		t.Fatalf("config/deploy.yml has %d top-level stop_timeout lines; want one", len(lines))
	}
	match := regexp.MustCompile(`^stop_timeout:[ \t]*([0-9]+)[ \t]*(?:#.*)?$`).FindStringSubmatch(lines[0])
	if match == nil {
		t.Fatal("stop_timeout must be a whole number of seconds")
	}
	seconds, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatal(err)
	}
	const loopJoinAndClose = time.Second
	const margin = 5 * time.Second
	if window, need := time.Duration(seconds)*time.Second, shutdownDrain+loopJoinAndClose+margin; window < need {
		t.Errorf("stop_timeout = %v; need at least %v for shutdown and margin", window, need)
	}
}

func TestShutdownStopsLoopsBeforeClose(t *testing.T) {
	// Each case makes one loop the slower one, so dropping either join lets the
	// database close while that loop is still running.
	for _, tc := range []struct {
		name          string
		sweep, backup time.Duration
	}{
		{"slow sweep", 3 * time.Second, time.Second},
		{"slow backup", time.Second, 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database, err := db.Open(filepath.Join(dir, "fixture.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()

			synctest.Test(t, func(t *testing.T) {
				ctx, stop := context.WithCancel(t.Context())
				defer stop()
				sweepDone := make(chan struct{})
				reporting := make(chan struct{})
				backups := sqlitekit.Backups{Dir: filepath.Join(dir, "backups"), Prefix: "fixture-", Layout: time.DateOnly, Keep: 1}
				loop, err := backups.Start(ctx, database, sqlitekit.BackupSchedule{
					Report: func(sqlitekit.BackupResult) {
						close(reporting)
						<-ctx.Done()
						time.Sleep(tc.backup)
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				<-reporting
				var sweeps sync.WaitGroup
				defer sweeps.Wait()
				sweeps.Go(func() {
					<-ctx.Done()
					// Cancellation alone doesn't mean an in-flight sweep has returned.
					time.Sleep(tc.sweep)
					close(sweepDone)
				})
				closeAfterLoops(stop, loop, &sweeps, func() error {
					select {
					case <-sweepDone:
					default:
						t.Error("database closed before the session sweep finished")
					}
					select {
					case <-loop.Done():
					default:
						t.Error("database closed before the backup loop finished")
					}
					return nil
				})
			})
		})
	}
}
