package main

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/17xande-dev/budget/internal/config"
	"github.com/17xande-dev/sqlitekit"
)

var sast = mustLoadLocation("Africa/Johannesburg")

func mustLoadLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err) // time/tzdata is embedded, so this cannot happen
	}
	return loc
}

// backups is the daily backup policy: budget-YYYY-MM-DD.db in BACKUP_DIR, one per
// South African day (the household's days, as everywhere else in the app), the
// newest BACKUP_KEEP kept. nil means backups are off (BACKUP_KEEP=0), which is
// also how the settings page knows to say so.
func backups(cfg config.Config) *sqlitekit.Backups {
	if cfg.BackupKeep == 0 {
		return nil
	}
	return &sqlitekit.Backups{
		Dir:      cfg.BackupDir,
		Prefix:   "budget-",
		Layout:   "2006-01-02",
		Keep:     cfg.BackupKeep,
		Location: sast,
	}
}

// backupDaily makes the day's backup at startup and then checks every `every`, so a
// server that was down at midnight still backs up the day it comes back. Run
// skips a day already done, which makes the hourly check nearly free. It must be
// the only caller of Run for its folder.
func backupDaily(ctx context.Context, d *sql.DB, b sqlitekit.Backups, every time.Duration) {
	run := func(now time.Time) {
		path, made, err := b.Run(ctx, d, now)
		switch {
		case err != nil:
			// Logged, and visible on the settings page as a backup going stale.
			log.Printf("backup: %v", err)
		case made:
			log.Printf("backup: wrote %s", path)
		}
	}
	run(time.Now())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			run(now)
		}
	}
}
