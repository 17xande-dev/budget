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

func startBackups(ctx context.Context, d *sql.DB, cfg config.Config) (*sqlitekit.BackupLoop, error) {
	b := backups(cfg)
	if b == nil {
		log.Print("backups are off (BACKUP_KEEP=0)")
		return nil, nil
	}
	return b.Start(ctx, d, sqlitekit.BackupSchedule{
		LockPath: cfg.DBPath + ".backup-lock",
		Report: func(result sqlitekit.BackupResult) {
			switch {
			case result.Err != nil:
				// A stale backup is also visible on the settings page.
				log.Printf("backup: %v", result.Err)
			case result.Made:
				log.Printf("backup: wrote %s", result.Path)
			}
		},
	})
}
