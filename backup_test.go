package main

import (
	"os"
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
func TestBackupsRunAtStartup(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "loop.db"), BackupDir: filepath.Join(dir, "backups"), BackupKeep: 3}
	d, err := db.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	b := backups(cfg)
	firstDay := time.Now().In(sast).Format(b.Layout)
	loop, err := startBackups(t.Context(), d, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		files, err := b.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 1 {
			lastDay := time.Now().In(sast).Format(b.Layout)
			if files[0].Name != b.Prefix+firstDay+".db" && files[0].Name != b.Prefix+lastDay+".db" {
				t.Errorf("backup %q, want today's SAST date", files[0].Name)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scheduled backups made no backup at startup")
		}
		time.Sleep(10 * time.Millisecond)
	}
	loop.Stop()
	if _, err := os.Stat(cfg.DBPath + ".backup-lock"); err != nil {
		t.Errorf("backup lock: %v", err)
	}
}

func TestBackupsOffDoesNotStartLoop(t *testing.T) {
	loop, err := startBackups(t.Context(), nil, config.Config{BackupKeep: 0})
	if loop != nil || err != nil {
		t.Fatalf("startBackups = %v, %v; want nil loop and no error", loop, err)
	}
}
