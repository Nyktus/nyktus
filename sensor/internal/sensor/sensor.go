// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sensor runs the honeypots of one configuration and reports their
// sessions to the trigger.
package sensor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/config"
	"nyktus.org/nyktus/sensor/internal/listener"
	"nyktus.org/nyktus/sensor/internal/reporter"
	"nyktus.org/nyktus/sensor/internal/session"
	"nyktus.org/nyktus/sensor/internal/telnet"
)

// Defaults of the process.
const (
	// DrainTimeout is how long the sensor delivers the queued sessions when it
	// stops.
	DrainTimeout = 15 * time.Second
	// StatsInterval is how often the sensor logs what it turned away or lost.
	// Anything an attacker can cause is counted and logged in one record per
	// interval, not one per occurrence.
	StatsInterval = time.Minute
)

// Options configure a run.
type Options struct {
	Config  *config.Config
	Version string
	Logger  *slog.Logger
	Clock   clock.Clock
	// Client sends the reports; nil means reporter.NewHTTPClient().
	Client *http.Client
	// DrainTimeout and StatsInterval replace the defaults.
	DrainTimeout  time.Duration
	StatsInterval time.Duration
	// Listening, if set, is called for each honeypot with the address it
	// listens on, before any session is served.
	Listening func(honeypotID string, addr net.Addr)
}

// service plays the protocol of one honeypot on a connection and records what
// the attacker did in the session. A service offers nothing real, and never
// runs or passes on what the attacker sent.
type service interface {
	Serve(ctx context.Context, conn net.Conn, s *session.Session)
}

// newService returns the service of a honeypot. The configuration has been
// validated, so the service is known.
func newService(hp config.Honeypot, clk clock.Clock) service {
	switch hp.Service {
	case config.Telnet:
		cfg := telnet.Config{Banner: telnet.DefaultBanner, LoginPrompt: telnet.DefaultLoginPrompt}
		if hp.Banner != nil {
			cfg.Banner = *hp.Banner
		}
		if hp.LoginPrompt != nil {
			cfg.LoginPrompt = *hp.LoginPrompt
		}
		return telnet.New(cfg, clk)
	default:
		panic("sensor: unknown service " + string(hp.Service))
	}
}

// honeypot is a handler of the listener: it opens a session for each
// connection, lets the service fill it and queues it when the connection ends.
type honeypot struct {
	hp       *session.Honeypot
	service  service
	clock    clock.Clock
	reporter *reporter.Reporter
	logger   *slog.Logger
}

func (h *honeypot) Handle(ctx context.Context, conn net.Conn) {
	remote, okRemote := addrPort(conn.RemoteAddr())
	local, okLocal := addrPort(conn.LocalAddr())
	if !okRemote || !okLocal {
		return
	}
	s, err := session.Start(h.clock, h.hp, remote, local)
	if err != nil {
		h.logger.ErrorContext(ctx, "sensor: session not started", h.hp.Attr(), slog.Any("error", err))
		return
	}
	// Also after a panic of the service: what the attacker did up to then is
	// reported.
	defer func() {
		s.End()
		h.reporter.Submit(s)
	}()
	h.service.Serve(ctx, conn, s)
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return tcp.AddrPort(), true
}

// bound is a honeypot with its listener.
type bound struct {
	hp     *session.Honeypot
	server *listener.Server
}

// Run binds the honeypots, serves them until ctx is done and delivers what is
// queued. A honeypot that cannot bind ends the start with an error: a sensor
// that silently runs fewer honeypots than configured is worse than none.
func Run(ctx context.Context, o Options) error {
	if o.Config == nil || o.Logger == nil || o.Clock == nil {
		panic("sensor: missing configuration, logger or clock")
	}
	if o.DrainTimeout <= 0 {
		o.DrainTimeout = DrainTimeout
	}
	if o.StatsInterval <= 0 {
		o.StatsInterval = StatsInterval
	}

	rep := reporter.New(reporter.Options{
		URL:    o.Config.TriggerURL,
		Client: o.Client,
		Clock:  o.Clock,
		Logger: o.Logger,
	})
	servers, err := bind(ctx, o, rep)
	if err != nil {
		return err
	}

	rep.Start()
	honeypots := make([]*session.Honeypot, 0, len(servers))
	var serving sync.WaitGroup
	for _, b := range servers {
		honeypots = append(honeypots, b.hp)
		o.Logger.InfoContext(ctx, "sensor: honeypot listening", b.hp.Attr(), slog.String("listen", b.server.Addr().String()))
		if o.Listening != nil {
			o.Listening(b.hp.ID, b.server.Addr())
		}
		serving.Go(func() { b.server.Serve(ctx) })
	}
	var background sync.WaitGroup
	background.Go(func() { rep.RunHeartbeats(ctx, o.Version, honeypots) })
	background.Go(func() {
		for o.Clock.Wait(ctx, o.StatsInterval) == nil {
			logStats(ctx, o.Logger, rep, servers)
		}
	})
	o.Logger.InfoContext(ctx, "sensor: started", slog.String("version", o.Version), slog.Int("honeypots", len(servers)))

	// The listeners end with ctx and close their connections, which queues
	// the sessions that were open.
	serving.Wait()
	background.Wait()

	after := context.WithoutCancel(ctx)
	drain, cancel := context.WithTimeout(after, o.DrainTimeout)
	defer cancel()
	rep.Shutdown(drain)
	logStats(after, o.Logger, rep, servers)
	o.Logger.InfoContext(after, "sensor: stopped")
	return nil
}

// bind opens the listener of every honeypot, or none.
func bind(ctx context.Context, o Options, rep *reporter.Reporter) ([]bound, error) {
	var (
		lc      net.ListenConfig
		servers []bound
	)
	for _, c := range o.Config.Honeypots {
		hp := &session.Honeypot{ID: c.ID, Service: string(c.Service), Secret: c.Secret}
		ln, err := lc.Listen(ctx, c.Network(), c.Listen)
		if err != nil {
			for _, b := range servers {
				_ = b.server.Close()
			}
			return nil, fmt.Errorf("honeypot %s: %w", c.ID, err)
		}
		servers = append(servers, bound{hp: hp, server: listener.New(listener.Options{
			Listener: ln,
			Clock:    o.Clock,
			Handler: &honeypot{
				hp:       hp,
				service:  newService(c, o.Clock),
				clock:    o.Clock,
				reporter: rep,
				logger:   o.Logger,
			},
		})})
	}
	return servers, nil
}

// logStats writes what the sensor turned away or lost since the last call. An
// attacker causes all of it, so each kind is one record per interval and holds
// counts only.
func logStats(ctx context.Context, logger *slog.Logger, rep *reporter.Reporter, servers []bound) {
	s := rep.TakeStats()
	if s.Overflow+s.Expired+s.Failed+s.Shutdown > 0 {
		logger.WarnContext(ctx, "sensor: reports not sent",
			slog.Int("overflow", s.Overflow), slog.Int("expired", s.Expired),
			slog.Int("failed", s.Failed), slog.Int("shutdown", s.Shutdown))
	}
	for _, b := range servers {
		st := b.server.TakeStats()
		if st.RefusedTotal+st.RefusedSource > 0 {
			logger.WarnContext(ctx, "sensor: connections refused", b.hp.Attr(),
				slog.Int("too_many", st.RefusedTotal), slog.Int("too_many_from_source", st.RefusedSource))
		}
		if st.AcceptErrors > 0 {
			logger.WarnContext(ctx, "sensor: accepting connections failed", b.hp.Attr(), slog.Int("errors", st.AcceptErrors))
		}
		if st.Panics > 0 {
			logger.ErrorContext(ctx, "sensor: sessions ended by a failure of the service", b.hp.Attr(),
				slog.Int("sessions", st.Panics), slog.String("panic", st.Panic), slog.String("stack", st.Stack))
		}
	}
}
