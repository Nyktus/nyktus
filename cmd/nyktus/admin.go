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
	"nyktus.org/nyktus/internal/auth/secondfactor"
	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/logging"
	"nyktus.org/nyktus/internal/user"
)

const adminUsage = `Usage: nyktus admin <command> [flags]

Commands:
  reset-password <email>   print a password reset link for an administrator
  remove-totp <email>      remove the TOTP factor of an administrator

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
	case "remove-totp":
		return removeTOTP(ctx, rest, src, stdout, stderr)
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
	return runAdminCommand(ctx, "reset-password", args, src, stdout, stderr, issueAdminResetLink)
}

// removeTOTP removes the TOTP factor of an administrator who lost both the
// authenticator and the recovery codes, when no other administrator can sign in
// to remove it. It needs no encryption keys, because it only deletes the
// factor. The password stays valid; combined with reset-password, it restores
// access to an account whose password is lost as well.
func removeTOTP(ctx context.Context, args []string, src config.Source, stdout, stderr io.Writer) error {
	return runAdminCommand(ctx, "remove-totp", args, src, stdout, stderr, removeAdminTOTP)
}

// runAdminCommand parses the address argument of the admin command name, loads
// the configuration and runs the command on the database of the console.
func runAdminCommand(ctx context.Context, name string, args []string, src config.Source, stdout, stderr io.Writer,
	run func(ctx context.Context, cfg config.Admin, svc *account.Service, email string, logger *slog.Logger, stdout io.Writer) error,
) error {
	fs := flag.NewFlagSet("admin "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: nyktus admin %s <email>\n", name)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if fs.NArg() != 1 {
		return usageError{fmt.Errorf("%s needs exactly one email address", name)}
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
	err = func() error {
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
		return run(ctx, cfg, account.NewService(pool, cfg.ConsoleURL), email, logger, stdout)
	}()
	if err != nil {
		return logFailure(ctx, logger, "admin "+name, err)
	}
	return nil
}

// adminError explains the errors that both admin commands share.
func adminError(err error, other string) error {
	switch {
	case errors.Is(err, user.ErrNotFound):
		return errors.New("no account has this email address")
	case errors.Is(err, account.ErrNotAdmin):
		return errors.New("the account is not an administrator; " + other)
	case errors.Is(err, account.ErrNotActive):
		return errors.New("the account is not active")
	}
	return err
}

func removeAdminTOTP(ctx context.Context, _ config.Admin, svc *account.Service, email string, logger *slog.Logger, stdout io.Writer) error {
	err := svc.RemoveAdminTOTP(ctx, email)
	if errors.Is(err, secondfactor.ErrNotEnabled) {
		return errors.New("the account has no TOTP factor")
	}
	if err != nil {
		return adminError(err, "an administrator removes the second factor of other accounts in the console")
	}
	_, err = fmt.Fprintf(stdout, `
The TOTP factor and the recovery codes of %s are removed, and every session
of the account has ended. The administrator signs in with the password alone
and should set up a new factor right away.

`, email)
	if err != nil {
		return fmt.Errorf("write confirmation: %w", err)
	}
	logger.InfoContext(ctx, "admin: TOTP factor removed")
	return nil
}

func issueAdminResetLink(ctx context.Context, _ config.Admin, svc *account.Service, email string, logger *slog.Logger, stdout io.Writer) error {
	link, err := svc.IssueAdminResetLink(ctx, email)
	if err != nil {
		return adminError(err, "an administrator resets other accounts in the console")
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
