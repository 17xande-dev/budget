package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/17xande-dev/budget/internal/config"
	"github.com/17xande-dev/budget/internal/db"
)

func TestBackupsFollowTheConfig(t *testing.T) {
	if b := backups(config.Config{BackupDir: "/x", BackupKeep: 0}); b != nil {
		t.Errorf("BACKUP_KEEP=0 gave %+v, want backups off (nil)", b)
	}
	b := backups(config.Config{BackupDir: "/data/backups", BackupKeep: 9})
	if b == nil || b.Dir != "/data/backups" || b.Keep != 9 || b.Prefix != "budget-" || b.Layout != "2006-01-02" {
		t.Fatalf("policy = %+v", b)
	}
	// The day is the household's: 23:30 UTC on the 5th is already the 6th in
	// Johannesburg, and the file is named for the 6th.
	d, err := db.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	b.Dir = filepath.Join(t.TempDir(), "backups")
	path, made, err := b.Run(t.Context(), d, time.Date(2026, 10, 5, 23, 30, 0, 0, time.UTC))
	if err != nil || !made || filepath.Base(path) != "budget-2026-10-06.db" {
		t.Fatalf("Run = %q, %v, %v; want budget-2026-10-06.db", path, made, err)
	}
}

// The loop is what makes a backup happen at all: it must call Run at startup (not
// an hour later) and the file it makes is the one the settings page lists.
func TestBackupDailyRunsAtStartup(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "loop.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	b := backups(config.Config{BackupDir: filepath.Join(t.TempDir(), "backups"), BackupKeep: 3})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		backupDaily(ctx, d, *b, time.Hour)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		files, err := b.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 1 {
			want := "budget-" + time.Now().In(sast).Format("2006-01-02") + ".db"
			if files[0].Name != want {
				t.Errorf("backup %q, want %q", files[0].Name, want)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backupDaily made no backup at startup")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
