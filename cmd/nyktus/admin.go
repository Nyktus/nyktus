// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"nyktus.org/nyktus/internal/auth/account"
	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/logging"
	"nyktus.org/nyktus/internal/user"
)

const adminUsage = `Usage: nyktus admin <command> [flags]

Commands:
  reset-password <email>   print a password reset link for an administrator

The commands use the configuration of the console.
`

func runAdmin(ctx context.Context, args []string, src config.Source, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, adminUsage)
		return usageError{errors.New("missing admin command")}
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "reset-password":
		return resetPassword(ctx, rest, src, stdout, stderr)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, adminUsage)
		return nil
	default:
		_, _ = fmt.Fprint(stderr, adminUsage)
		return usageError{fmt.Errorf("unknown admin command %q", cmd)}
	}
}

// resetPassword prints a password reset link for an administrator, so that an
// operator can regain access when no administrator can sign in. It prints a link
// instead of setting a password, so that no password passes through the terminal
// or the shell history and the administrator chooses it alone. Other accounts are
// reset by an administrator in the console.
func resetPassword(ctx context.Context, args []string, src config.Source, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin reset-password", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), "Usage: nyktus admin reset-password <email>\n")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if fs.NArg() != 1 {
		return usageError{errors.New("reset-password needs exactly one email address")}
	}
	email, err := user.ParseEmail(fs.Arg(0))
	if err != nil {
		return usageError{fmt.Errorf("invalid email address: %w", err)}
	}

	cfg, err := config.LoadAdmin(src)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	logger := logging.New(stderr, cfg.LogLevel)
	if err := issueAdminResetLink(ctx, cfg, email, logger, stdout); err != nil {
		return logFailure(ctx, logger, "admin reset-password", err)
	}
	return nil
}

func issueAdminResetLink(ctx context.Context, cfg config.Admin, email string, logger *slog.Logger, stdout io.Writer) error {
	pool, err := db.Open(ctx, cfg.DatabaseURL.Value(), db.Options{MaxConns: 1})
	if err != nil {
		return err
	}
	defer pool.Close()
	if cfg.Environment != config.Development {
		if err := db.CheckLeastPrivilege(ctx, pool); err != nil {
			return err
		}
	}

	link, err := account.NewService(pool, cfg.ConsoleURL).IssueAdminResetLink(ctx, email)
	switch {
	case errors.Is(err, user.ErrNotFound):
		return errors.New("no account has this email address")
	case errors.Is(err, account.ErrNotAdmin):
		return errors.New("the account is not an administrator; an administrator resets other accounts in the console")
	case errors.Is(err, account.ErrNotActive):
		return errors.New("the account is not active")
	case err != nil:
		return err
	}
	// The link is a secret, so it goes to stdout and the log only records that it
	// was issued.
	_, err = fmt.Fprintf(stdout, `
Password reset link for %s. Pass it on to the administrator, who sets a new
password with it. The link works once and is valid until %s. The current
password and sessions stay valid until the link is used.

    %s

`, email, link.ExpiresAt.UTC().Format(time.RFC3339), link.URL)
	if err != nil {
		return fmt.Errorf("write password reset link: %w", err)
	}
	logger.InfoContext(ctx, "admin: password reset link issued", slog.Any("link", link))
	return nil
}
