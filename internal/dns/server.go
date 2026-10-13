// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/netutil"
)

// Limits of the servers. A query is small and answered at once, so the time a
// client may take is short, and a connection over TCP serves a few queries at
// most, so that clients cannot hold the connections.
const (
	readTimeout     = 2 * time.Second
	writeTimeout    = 2 * time.Second
	tcpIdleTimeout  = 10 * time.Second
	maxTCPConns     = 128
	maxTCPQueries   = 16
	shutdownTimeout = 5 * time.Second
)

// Serve answers queries over UDP on pc and over TCP on ln until ctx is
// canceled. It calls started once both servers accept queries, and records
// the queued queries before it returns.
func Serve(ctx context.Context, h *Handler, pc net.PacketConn, ln net.Listener, started func()) error {
	udpStarted, tcpStarted := make(chan struct{}), make(chan struct{})
	udp := &dns.Server{
		PacketConn:        pc,
		Handler:           h,
		UDPSize:           ednsUDPSize,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		MsgAcceptFunc:     acceptMsg,
		NotifyStartedFunc: func() { close(udpStarted) },
	}
	tcp := &dns.Server{
		Listener:          netutil.LimitListener(ln, maxTCPConns),
		Handler:           h,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       func() time.Duration { return tcpIdleTimeout },
		MaxTCPQueries:     maxTCPQueries,
		MsgAcceptFunc:     acceptMsg,
		NotifyStartedFunc: func() { close(tcpStarted) },
	}

	stopRecording := h.startRecording(ctx)
	errs := make(chan error, 2)
	go func() { errs <- udp.ActivateAndServe() }()
	go func() { errs <- tcp.ActivateAndServe() }()

	var err error
	for _, ch := range []chan struct{}{udpStarted, tcpStarted} {
		select {
		case <-ch:
		case err = <-errs:
		case <-ctx.Done():
		}
		if err != nil || ctx.Err() != nil {
			break
		}
	}
	if err == nil && ctx.Err() == nil {
		started()
		select {
		case err = <-errs:
		case <-ctx.Done():
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	// A server that has not started or has already failed reports so on
	// shutdown; that is no further error.
	_ = udp.ShutdownContext(shutdownCtx)
	_ = tcp.ShutdownContext(shutdownCtx)
	_ = pc.Close()
	_ = ln.Close()
	stopRecording()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("serve dns: %w", err)
	}
	return nil
}

// acceptMsg rejects what the DNS role does not answer before the handler
// runs: opcodes other than QUERY, such as NOTIFY, which the default of the
// library accepts, receive NOTIMP. The default ignores responses, so that two
// servers cannot be made to answer each other in a loop, and answers a message
// without exactly one question with FORMERR.
func acceptMsg(dh dns.Header) dns.MsgAcceptAction {
	if opcode := int(dh.Bits>>11) & 0xF; opcode != dns.OpcodeQuery && dh.Bits&(1<<15) == 0 {
		return dns.MsgRejectNotImplemented
	}
	return dns.DefaultMsgAcceptFunc(dh)
}
