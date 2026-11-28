// Command budget is a household budgeting app: FNB transactions in, categorised
// spending against monthly targets out. See README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	// distroless/static carries no zoneinfo, and the schedule (and anything
	// showing a South African date) needs Africa/Johannesburg. ~450 KB.
	_ "time/tzdata"

	"github.com/17xande-dev/budget/internal/auth"
	"github.com/17xande-dev/budget/internal/budget"
	"github.com/17xande-dev/budget/internal/config"
	"github.com/17xande-dev/budget/internal/db"
	"github.com/17xande-dev/budget/internal/fetch"
	"github.com/17xande-dev/budget/internal/fnb"
	"github.com/17xande-dev/budget/internal/handler"
	"github.com/17xande-dev/budget/internal/ledger"
	"github.com/17xande-dev/budget/internal/mcpserver"
	"github.com/17xande-dev/budget/internal/middleware"
	"github.com/17xande-dev/password"
	"github.com/17xande-dev/ratelimit"
	"github.com/17xande-dev/ratelimit/clientip"
	"github.com/17xande-dev/sqlitekit"
	"golang.org/x/time/rate"
)

// version is reported to MCP clients; set at build time with
// -ldflags "-X main.version=...".
var version = "dev"

const shutdownDrain = 15 * time.Second

func main() {
	// The per-IP limiter admits a burst; ten parallel Argon2id logins measured
	// about 650 MiB against a 512 MiB container. Cap both the server and the
	// reset-password command at two concurrent hashes; excess callers wait.
	password.SetConcurrency(2)

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		if err := runCommand(cfg, os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if err := serve(cfg); err != nil {
		log.Fatal(err)
	}
}

// runCommand runs an operator subcommand. These exist as subcommands of the one
// binary, rather than separate cmd/ programs, because the runtime image is
// distroless: `docker compose exec budget /budget reset-password ...` works there
// with no shell and no sqlite3.
func runCommand(cfg config.Config, args []string) error {
	switch args[0] {
	case "reset-password":
		if len(args) != 2 {
			return errors.New("usage: budget reset-password EMAIL  (new password on stdin)")
		}
		d, err := db.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		defer d.Close()
		return resetPassword(auth.NewStore(d), args[1], os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("unknown command %q (known: reset-password)", args[0])
	}
}

func serve(cfg config.Config) error {
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	var backupLoop *sqlitekit.BackupLoop
	var sweeps sync.WaitGroup
	defer func() { closeAfterLoops(stop, backupLoop, &sweeps, database.Close) }()

	users := auth.NewStore(database)
	if err := ensureSetupToken(users, cfg.SetupToken.Reveal(), log.Default()); err != nil {
		return fmt.Errorf("setup token: %w", err)
	}

	led, bud := ledger.NewStore(database), budget.NewStore(database)
	fetcher := fetch.New(database, fnb.Chrome{URL: cfg.FNB.ChromeURL}, led, bud, fetch.Config{
		Creds:    fnb.Credentials{Username: cfg.FNB.Username, Password: cfg.FNB.Password.Reveal(), Profile: cfg.FNB.Profile},
		Products: cfg.FNB.Products,
		Hour:     cfg.FNB.Hour,
		Minute:   cfg.FNB.Minute,
	})
	users.Life = auth.Lifetime(cfg.SessionTTL)
	if err := users.Life.Validate(); err != nil {
		return fmt.Errorf("session lifetime: %w", err)
	}
	h, err := handler.New(users, led, bud, handler.Config{
		Fetcher:        fetcher,
		Backups:        backups(cfg),
		PublicOrigin:   cfg.PublicOrigin,
		CookieSecure:   cfg.CookieSecure,
		SessionTTL:     cfg.SessionTTL,
		ClientIPSource: cfg.ClientIPSource,
	})
	if err != nil {
		return fmt.Errorf("init handler: %w", err)
	}

	// One per-IP ceiling for every route that verifies a secret. Generous enough
	// that a fumbled password or two never trips it; the per-email tier inside
	// the login handler is the tight one.
	secretLimit, err := newSecretLimit(cfg.ClientIPSource)
	if err != nil {
		return fmt.Errorf("init rate limit: %w", err)
	}

	mcp, err := mcpserver.New(mcpserver.Deps{Users: users, Ledger: led, Budget: bud, ClientIPSource: cfg.ClientIPSource, Version: version})
	if err != nil {
		return fmt.Errorf("init mcp: %w", err)
	}

	app := h.Server(middleware.RequireUser(users, h.SessionCookie()), secretLimit, mcp.Handler())

	srv := newServer(":"+cfg.Port, app)

	backupLoop, err = startBackups(ctx, database, cfg)
	if err != nil {
		return fmt.Errorf("backups: %w", err)
	}

	// Expired sessions are already refused on read; this only keeps the table
	// from growing for ever.
	sweeps.Go(func() { sweepSessions(ctx, users, time.Hour) })
	// A bank fetch can take 30 seconds. Cancel its scheduler with ctx, but
	// don't wait for a fetch to finish within the container stop window.
	go fetcher.Schedule(ctx)

	errc := make(chan error, 1)
	go func() {
		log.Printf("listening on :%s", cfg.Port)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Print("shutting down")
	// config/deploy.yml allows 25 seconds for the HTTP drain, loop joins and
	// database close, with at least five seconds to spare.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownDrain)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func closeAfterLoops(stop context.CancelFunc, backups *sqlitekit.BackupLoop, sweeps *sync.WaitGroup, closeDB func() error) {
	// A listener failure can reach this defer without a signal cancelling ctx.
	stop()
	backups.Stop()
	sweeps.Wait()
	_ = closeDB()
}

// newServer is the http.Server with the app's timeouts and header limit.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// The default is 1 MB. Header values (a client address among them) key
		// the rate limiters, so keep them small.
		MaxHeaderBytes: 64 << 10,
	}
}

func sweepSessions(ctx context.Context, store *auth.Store, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n, err := store.DeleteExpiredSessions(ctx, now); err != nil && ctx.Err() == nil {
				log.Printf("sweep sessions: %v", err)
			} else if n > 0 {
				log.Printf("swept %d expired session(s)", n)
			}
		}
	}
}

// newSecretLimit is the per-IP ceiling for every route that verifies a secret,
// reading the client address as source says to. Fail-closed: a full table
// refuses new addresses.
func newSecretLimit(source clientip.Source) (func(http.Handler) http.Handler, error) {
	l, err := ratelimit.New(ratelimit.Config{Rate: rate.Every(10 * time.Second), Burst: 10, IdleTTL: 30 * time.Minute})
	if err != nil {
		return nil, err
	}
	return middleware.ByIP(l, source), nil
}
