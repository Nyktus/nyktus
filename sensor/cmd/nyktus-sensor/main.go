// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nyktus-sensor runs the honeypots of a monitored network and reports
// what attackers do to the Nyktus trigger.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/config"
	"nyktus.org/nyktus/sensor/internal/sensor"
	"nyktus.org/nyktus/sensor/internal/version"
)

const usage = `Usage: nyktus-sensor <command> -config <file>

Commands:
  run       run the honeypots of the configuration
  check     check the configuration and exit
  version   print the version

Run "nyktus-sensor <command> -h" for the flags of a command.
`

// Exit codes. Usage errors are distinguished from runtime failures so that
// scripts can tell a wrong invocation from a failed operation.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Restoring the default signal handling on the first signal lets a second
	// one end the process while it is still delivering its reports.
	context.AfterFunc(ctx, stop)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}

	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "run":
		err = runSensor(ctx, rest, stderr)
	case "check":
		err = check(rest, stdout, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, version.Current())
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}

	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.As(err, &usageErr):
		_, _ = fmt.Fprintln(stderr, err)
		return exitUsage
	default:
		_, _ = fmt.Fprintln(stderr, err)
		return exitFailure
	}
}

// configFlag parses the flags of a command, which takes the path of the
// configuration only.
func configFlag(name string, args []string, stderr io.Writer) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path of the configuration file (required)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", err
		}
		return "", usageError{err}
	}
	if fs.NArg() > 0 {
		return "", usageError{fmt.Errorf("unexpected arguments: %v", fs.Args())}
	}
	if *path == "" {
		return "", usageError{errors.New("flag -config is required")}
	}
	return *path, nil
}

// check validates the configuration, including the files it names, without
// binding a port or contacting the trigger.
func check(args []string, stdout, stderr io.Writer) error {
	path, err := configFlag("check", args, stderr)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	_, _ = fmt.Fprintf(stdout, "configuration ok: %d honeypots\n", len(cfg.Honeypots))
	return nil
}

func runSensor(ctx context.Context, args []string, stderr io.Writer) error {
	path, err := configFlag("run", args, stderr)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	if err := sensor.Run(ctx, sensor.Options{
		Config:  cfg,
		Version: version.Current(),
		Logger:  logger,
		Clock:   clock.NewSystem(),
	}); err != nil {
		logger.ErrorContext(ctx, "sensor: failed", slog.Any("error", err))
		return errors.New("the sensor did not start")
	}
	return nil
}
