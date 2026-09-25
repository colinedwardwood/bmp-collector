// Package bmpcollector implements a minimal BMP (BGP Monitoring Protocol,
// RFC 7854) collector: it accepts inbound TCP connections from routers,
// frames and decodes BMP messages, and hands decoded records to a
// caller-supplied callback.
//
// SPIKE / PROTOTYPE (2026-09-25): see README.md for status and open
// questions. This is not a production-hardened implementation.
//
// The wire-format decoding (BMP envelope + inner BGP UPDATE) is not
// reimplemented here. It is delegated entirely to
// github.com/osrg/gobgp/v3/pkg/packet/bmp (and its bgp sub-package),
// which already implements the full RFC 7854 message set and exposes a
// bufio.SplitFunc (bmp.SplitBMP) for framing a raw TCP byte stream into
// discrete messages. This package only adds the TCP accept/serve
// lifecycle and a Start(ctx)/Shutdown(ctx)-shaped API around it.
package bmpcollector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// maxBMPMessageSize is a defensive upper bound on a single BMP message's
// declared length, so a malformed or hostile peer can't make the scanner
// buffer unbounded memory. RFC 7854 doesn't specify a hard max; this is a
// generous, arbitrary prototype-stage limit (BGP UPDATEs are typically
// well under 64KiB even with today's route-refresh/EOR/attribute sizes).
const maxBMPMessageSize = 1 << 20 // 1 MiB

// Record is one decoded BMP message, handed to the callback.
//
// Message and PeerHeader are exactly the gobgp bmp package's own types
// (bmp.BMPMessage embeds bmp.BMPPeerHeader and a bmp.BMPHeader). This
// prototype deliberately does not re-wrap them into project-owned DTOs
// yet -- see README.md "Open questions" for the tradeoff. Consumers
// should treat Message/PeerHeader as read-only.
type Record struct {
	// ReceivedAt is when this collector finished decoding the message
	// (not a timestamp carried on the wire).
	ReceivedAt time.Time

	// RouterAddr is the remote TCP address of the BMP-speaking router
	// that this message arrived on (i.e. the monitored router itself,
	// not the BMP "monitored peer" described inside PeerHeader).
	RouterAddr net.Addr

	// PeerHeader is the decoded per-peer identity for message types
	// that carry one (all types except Initiation/Termination, per
	// RFC 7854 §4.1). It is the zero value for those two types.
	PeerHeader bmp.BMPPeerHeader

	// Message is the fully decoded BMP message: Header + PeerHeader +
	// a type-specific Body (one of bmp.BMPRouteMonitoring,
	// BMPStatisticsReport, BMPPeerUpNotification,
	// BMPPeerDownNotification, BMPInitiation, BMPTermination,
	// BMPRouteMirroring).
	Message *bmp.BMPMessage

	// Raw holds the original wire bytes for this one message, for
	// reprocessing, debugging, or re-decoding with different options.
	// It is a copy; callers may retain it safely.
	Raw []byte
}

// Callback is invoked once per successfully decoded BMP message. It runs
// on the per-connection goroutine that received the message, so it must
// not block for long and must not call back into the Collector.
type Callback func(Record)

// ErrorCallback is invoked once per per-connection error (decode failure
// or I/O error) that terminates that connection's read loop. It is
// optional; if nil, errors are only logged.
type ErrorCallback func(routerAddr net.Addr, err error)

// Collector is a BMP monitoring station: it listens for inbound TCP
// connections from routers acting as BMP clients (RFC 7854 -- BMP is
// always initiated by the monitored router, dialing out to the
// collector), and decodes every BMP message on every connection.
//
// The zero value is not usable; construct with New.
type Collector struct {
	listenAddr string
	onRecord   Callback
	onError    ErrorCallback
	logger     *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	started  bool
	closed   bool
}

// Option configures optional Collector behavior.
type Option func(*Collector)

// WithErrorCallback sets a callback invoked on per-connection decode/IO
// errors (in addition to logging).
func WithErrorCallback(cb ErrorCallback) Option {
	return func(c *Collector) { c.onError = cb }
}

// WithLogger overrides the default slog logger (slog.Default()).
func WithLogger(l *slog.Logger) Option {
	return func(c *Collector) { c.logger = l }
}

// New constructs a Collector that will listen on listenAddr (e.g.
// "0.0.0.0:1790" -- RFC 7854 assigns no well-known port; 1790 mirrors the
// gobgp package's own bmp.BMP_DEFAULT_PORT... note that constant is
// actually 11019 in this gobgp release, so callers should pick and
// document their own port rather than assume a de facto standard one).
// cb is called once per decoded message; it must not be nil.
func New(listenAddr string, cb Callback, opts ...Option) *Collector {
	if cb == nil {
		panic("bmpcollector: New called with nil Callback")
	}
	c := &Collector{
		listenAddr: listenAddr,
		onRecord:   cb,
		logger:     slog.Default(),
		conns:      make(map[net.Conn]struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Start binds the TCP listener and begins accepting router connections.
// It returns once the listener is bound; the accept loop and all
// per-connection read loops run in background goroutines until Shutdown
// is called or ctx is done.
//
// Start must be called at most once.
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("bmpcollector: Start called more than once")
	}
	c.started = true
	c.mu.Unlock()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", c.listenAddr)
	if err != nil {
		return fmt.Errorf("bmpcollector: listen on %s: %w", c.listenAddr, err)
	}

	c.mu.Lock()
	c.listener = ln
	c.mu.Unlock()

	c.wg.Add(1)
	go c.acceptLoop(ctx, ln)

	// If the caller's context is cancelled, tear the listener (and
	// therefore the accept loop) down proactively rather than waiting
	// for the next Accept to fail on its own.
	go func() {
		<-ctx.Done()
		_ = c.closeListener()
	}()

	c.logger.Info("bmpcollector: listening", "addr", ln.Addr().String())
	return nil
}

func (c *Collector) acceptLoop(ctx context.Context, ln net.Listener) {
	defer c.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed || ctx.Err() != nil {
				return
			}
			c.logger.Error("bmpcollector: accept failed", "err", err)
			return
		}

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = conn.Close()
			return
		}
		c.conns[conn] = struct{}{}
		c.mu.Unlock()

		c.wg.Add(1)
		go c.serveConn(ctx, conn)
	}
}

func (c *Collector) serveConn(ctx context.Context, conn net.Conn) {
	defer c.wg.Done()
	defer func() {
		c.mu.Lock()
		delete(c.conns, conn)
		c.mu.Unlock()
		_ = conn.Close()
	}()

	remote := conn.RemoteAddr()
	c.logger.Info("bmpcollector: router connected", "addr", remote.String())

	// Closing the connection is the only way to unblock a Scanner
	// that's blocked in Read once Shutdown/ctx-done wants out; that
	// happens via Shutdown's/ctx-watcher's conn.Close() calls, which
	// make the read below return an error and the scanner loop exit.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), maxBMPMessageSize)
	scanner.Split(bmp.SplitBMP)

	for scanner.Scan() {
		raw := append([]byte(nil), scanner.Bytes()...) // copy: Scanner reuses its buffer
		msg, err := bmp.ParseBMPMessage(raw)
		if err != nil {
			c.logger.Warn("bmpcollector: failed to decode BMP message", "addr", remote.String(), "err", err)
			if c.onError != nil {
				c.onError(remote, fmt.Errorf("decode: %w", err))
			}
			continue
		}

		c.onRecord(Record{
			ReceivedAt: time.Now(),
			RouterAddr: remote,
			PeerHeader: msg.PeerHeader,
			Message:    msg,
			Raw:        raw,
		})
	}

	if err := scanner.Err(); err != nil {
		c.logger.Warn("bmpcollector: connection read error", "addr", remote.String(), "err", err)
		if c.onError != nil {
			c.onError(remote, fmt.Errorf("read: %w", err))
		}
	}
	c.logger.Info("bmpcollector: router disconnected", "addr", remote.String())
}

func (c *Collector) closeListener() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listener == nil || c.closed {
		return nil
	}
	c.closed = true
	return c.listener.Close()
}

// Shutdown closes the listener and every open per-router connection, then
// waits for all in-flight goroutines to exit or for ctx to be done,
// whichever comes first.
func (c *Collector) Shutdown(ctx context.Context) error {
	_ = c.closeListener()

	c.mu.Lock()
	conns := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
