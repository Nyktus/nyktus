// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nyktus runs the Nyktus server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"nyktus.org/nyktus/internal/auth/password"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/console"
	"nyktus.org/nyktus/internal/platform/buildinfo"
	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/platform/logging"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/migrations"
)

const usage = `Usage: nyktus <command> [flags]

Commands:
  serve     run the server roles
  migrate   apply pending database migrations
  admin     administer accounts when no administrator can sign in
  version   print the version

Run "nyktus <command> -h" for the flags of a command.
`

// Exit codes. Usage errors are distinguished from runtime failures so that scripts
// can tell a wrong invocation from a failed operation.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Restoring the default signal handling on the first signal lets a second one
	// end the process while it is still shutting down gracefully.
	context.AfterFunc(ctx, stop)
	code := run(ctx, os.Args[1:], config.FromEnvironment(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, src config.Source, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}

	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "serve":
		err = serve(ctx, rest, src, stdout, stderr)
	case "migrate":
		err = runMigrate(ctx, rest, src, stderr)
	case "admin":
		err = runAdmin(ctx, rest, src, stdout, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, buildinfo.Version())
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}

	var usageErr usageError
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errLogged):
		return exitFailure
	case errors.As(err, &usageErr):
		_, _ = fmt.Fprintln(stderr, err)
		return exitUsage
	default:
		_, _ = fmt.Fprintln(stderr, err)
		return exitFailure
	}
}

// errLogged reports a failure that has already been written to the log. Once the
// logger exists, failures go through it, so that the output stays parseable JSON.
var errLogged = errors.New("failure logged")

func logFailure(ctx context.Context, logger *slog.Logger, command string, err error) error {
	logger.ErrorContext(ctx, "nyktus: command failed", slog.String("command", command), slog.Any("error", err))
	return errLogged
}

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Errorf("unexpected arguments: %v", fs.Args())}
	}
	return nil
}

func serve(ctx context.Context, args []string, src config.Source, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rolesFlag := fs.String("roles", "", "comma-separated roles to run (default: all)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	roles, err := config.ParseRoles(*rolesFlag)
	if err != nil {
		return usageError{err}
	}

	cfg, err := config.LoadServe(src, roles)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	logger := logging.New(stderr, cfg.LogLevel)
	logger.InfoContext(ctx, "nyktus: starting",
		slog.String("version", buildinfo.Version()),
		slog.Any("roles", cfg.Roles),
		slog.String("environment", string(cfg.Environment)),
	)

	if err := serveConsole(ctx, cfg, logger, stdout); err != nil {
		return logFailure(ctx, logger, "serve", err)
	}
	return nil
}

func serveConsole(ctx context.Context, cfg config.Serve, logger *slog.Logger, stdout io.Writer) error {
	pool, err := db.Open(ctx, cfg.Console.DatabaseURL.Value(), db.Options{})
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}
	defer pool.Close()

	if cfg.Environment != config.Development {
		if err := db.CheckLeastPrivilege(ctx, pool); err != nil {
			return fmt.Errorf("console: %w", err)
		}
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Console.Addr)
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}
	logger.InfoContext(ctx, "console: listening", slog.String("addr", ln.Addr().String()))

	setupService := setup.NewService(pool)
	handler, err := console.New(ctx, console.Options{
		Logger:         logger,
		DB:             pool,
		Setup:          setupService,
		Hasher:         password.NewHasher(),
		Sessions:       session.Config{IdleTimeout: cfg.Console.SessionIdleTimeout, MaxAge: cfg.Console.SessionMaxAge},
		ConsoleURL:     cfg.Console.URL,
		TrustedProxies: cfg.TrustedProxies,
	})
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("console: %w", err)
	}
	// The setup token is issued only once the console can accept the request that
	// uses it, so that a start that fails leaves no valid token behind.
	if err := announceSetup(ctx, setupService, cfg.Console.URL, logger, stdout); err != nil {
		_ = ln.Close()
		return fmt.Errorf("console: %w", err)
	}
	srv := httpx.NewServer(handler, logger)
	if err := httpx.Serve(ctx, srv, ln); err != nil {
		return fmt.Errorf("console: %w", err)
	}
	logger.InfoContext(ctx, "console: stopped")
	return nil
}

// announceSetup issues a setup token while no administrator exists and writes the
// setup URL to stdout. The token is a secret, so it is kept out of the log, which
// goes to stderr; the log only records that the setup is pending.
func announceSetup(ctx context.Context, svc *setup.Service, consoleURL string, logger *slog.Logger, stdout io.Writer) error {
	t, ok, err := svc.Issue(ctx)
	if err != nil || !ok {
		return err
	}
	if err := setup.WriteInstructions(stdout, consoleURL, t); err != nil {
		return fmt.Errorf("write setup instructions: %w", err)
	}
	logger.InfoContext(ctx, "console: setup pending", slog.Any("token", t))
	return nil
}

func runMigrate(ctx context.Context, args []string, src config.Source, stderr io.Writer) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	cfg, err := config.LoadMigrate(src)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	logger := logging.New(stderr, cfg.LogLevel)

	if err := applyMigrations(ctx, cfg, logger); err != nil {
		return logFailure(ctx, logger, "migrate", err)
	}
	return nil
}

func applyMigrations(ctx context.Context, cfg config.Migrate, logger *slog.Logger) error {
	all, err := migrate.Load(migrations.FS)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL.Value(), db.Options{MaxConns: 1})
	if err != nil {
		return err
	}
	defer pool.Close()

	n, err := migrate.Apply(ctx, pool, all, logger)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "migrate: done", slog.Int("applied", n), slog.Int("total", len(all)))
	return nil
}
