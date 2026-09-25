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
// lifecycle and a Start(ctx)/Shutdown(ctx)-shaped API around it -- plus,
// as of this revision, its own framing validation layered on top of
// gobgp's decoder (see splitBMPMessage) because gobgp's own bmp.SplitBMP
// does not safely handle every malformed-header case a hostile or buggy
// peer can send (see the fix notes there).
package bmpcollector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
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

// Defaults for the connection-level resource limits added to guard
// against resource exhaustion (see WithMaxConnections, WithIdleTimeout,
// WithTCPKeepAlive). These are prototype-stage, deliberately generous
// defaults; a real deployment should tune them for its expected peer
// count and BMP traffic pattern.
const (
	// defaultMaxConnections caps how many router connections this
	// Collector will hold open concurrently. Without a cap, a
	// connection flood (accidental or hostile) can exhaust file
	// descriptors and goroutines with no backpressure.
	defaultMaxConnections = 1024

	// defaultIdleTimeout is how long a connection may go without any
	// data being read from it before it is closed. RFC 7854 defines
	// no BMP-layer keepalive, so an idle timeout here is this
	// collector's own guard against a peer that opens a connection
	// and then never sends (or stalls forever mid-message): without
	// it, that peer parks a goroutine and a file descriptor forever.
	defaultIdleTimeout = 10 * time.Minute

	// defaultKeepAlivePeriod is the OS-level TCP keepalive probe
	// interval enabled on every accepted connection, so a peer that
	// vanishes without a clean TCP close (power loss, pulled cable,
	// a middlebox that silently drops the session) is eventually
	// detected and the connection is torn down instead of parked
	// forever.
	defaultKeepAlivePeriod = 30 * time.Second
)

// bmpHeaderSize mirrors bmp.BMP_HEADER_SIZE (version(1) + length(4) +
// type(1) = 6 bytes). Kept as a local named constant purely for
// readability in splitBMPMessage; it is asserted equal to gobgp's own
// constant in collector_test.go so the two can't silently drift.
const bmpHeaderSize = bmp.BMP_HEADER_SIZE

// errInvalidBMPHeader is returned by splitBMPMessage (and surfaces via
// bufio.Scanner.Err(), and from there to serveConn's ErrorCallback) when
// a connection sends a BMP header this collector cannot safely
// resynchronize past: either the fixed version byte doesn't match
// bmp.BMP_VERSION, or the declared Length is smaller than the header
// itself (or larger than this collector will ever accept). BMP (RFC
// 7854) has no self-synchronizing marker between messages -- the only
// length field in the stream is the one we just decided we can't trust
// -- so unlike, say, a line-oriented protocol there is no safe way to
// "skip forward a byte and try again" without risking either an
// unbounded resync scan or silently reinterpreting the middle of what
// was actually a valid message as a new header. Terminating the
// connection (the peer is expected to reconnect and resend a
// well-formed stream) is the correct "reject" behavior here, and is what
// distinguishes this from a transient "need more data" condition.
var errInvalidBMPHeader = errors.New("bmpcollector: invalid BMP header")

// splitBMPMessage is a bufio.SplitFunc used in place of gobgp's own
// bmp.SplitBMP. It reuses gobgp's bmp.BMPHeader.DecodeFromBytes for the
// actual header decode (so behavior stays in sync with gobgp's own
// notion of a valid header), but adds validation gobgp's SplitBMP
// omits, and reacts differently to invalid input:
//
//   - CRITICAL fix (a Length that doesn't even cover the header):
//     gobgp's bmp.SplitBMP decodes the header, and if that decode
//     succeeds -- which only checks the version byte, not Length -- it
//     unconditionally returns (advance=int(Length), token=data[0:Length],
//     err=nil). A peer that sends a syntactically valid 6-byte header
//     with Length=0 makes it return (0, <a non-nil, 0-byte slice>, nil)
//     forever. bufio.Scanner treats a non-nil token (even a 0-byte one)
//     as a successfully produced token and returns true from Scan()
//     without ever calling Read() again -- so the connection's read loop
//     spins at ~100% CPU in a tight loop that never blocks in a syscall,
//     which means closing the connection (Shutdown's only unblock
//     mechanism for a goroutine blocked in a network Read) cannot
//     interrupt it. This function explicitly requires Length >=
//     bmpHeaderSize before treating a header as usable, and rejects the
//     connection outright (returns an error) otherwise.
//   - CRITICAL fix (an invalid version byte): gobgp's bmp.SplitBMP hits
//     BMPHeader.DecodeFromBytes' one error case (the version check) and
//     returns (0, nil, nil) -- bufio.Scanner correctly reads this as
//     "need more data" and calls Read() again, but because the
//     already-buffered poisoned bytes are never skipped, every
//     subsequent Scan() re-decodes the same bad header first. The
//     connection silently stops producing any messages forever, even if
//     the peer sends perfectly well-formed ones afterward -- a
//     permanent, silent block. This function instead rejects the
//     connection immediately on a bad version byte.
//   - A Length larger than maxBMPMessageSize is also rejected outright,
//     rather than relying solely on bufio.Scanner's own "buffer would
//     need to grow past its max" error (bufio.ErrTooLong), so the
//     failure mode is this package's own, clearly-attributed error.
func splitBMPMessage(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < bmpHeaderSize {
		if atEOF && len(data) > 0 {
			// A connection that closes mid-header. Not a decode
			// attack, just a truncated stream; report it as an
			// ordinary read-side error rather than the harsher
			// errInvalidBMPHeader.
			return 0, nil, fmt.Errorf("bmpcollector: connection closed with a truncated BMP header (%d of %d bytes)", len(data), bmpHeaderSize)
		}
		// Ask for more data. This is the ordinary "haven't read a
		// full header yet" case, identical to gobgp's own SplitBMP
		// here.
		return 0, nil, nil
	}

	hdr := &bmp.BMPHeader{}
	if decodeErr := hdr.DecodeFromBytes(data[:bmpHeaderSize]); decodeErr != nil {
		// gobgp only returns an error here for an unrecognized
		// version byte (see BMPHeader.DecodeFromBytes). Reject the
		// connection rather than waiting on an already-poisoned
		// buffer for more data that can never produce a valid
		// token.
		return 0, nil, fmt.Errorf("%w: %v", errInvalidBMPHeader, decodeErr)
	}

	// gobgp's BMPHeader.DecodeFromBytes only validates Version; it
	// does not check that Length is large enough to even contain the
	// 6-byte header it was just decoded from. Enforce that ourselves
	// -- this is the fix for the Length=0 busy-loop described above.
	if hdr.Length < uint32(bmpHeaderSize) {
		return 0, nil, fmt.Errorf("%w: length=%d is smaller than the %d-byte header", errInvalidBMPHeader, hdr.Length, bmpHeaderSize)
	}
	if hdr.Length > uint32(maxBMPMessageSize) {
		return 0, nil, fmt.Errorf("%w: length=%d exceeds max message size %d", errInvalidBMPHeader, hdr.Length, maxBMPMessageSize)
	}

	if uint32(len(data)) < hdr.Length {
		if atEOF {
			return 0, nil, fmt.Errorf("bmpcollector: connection closed mid-message (want %d bytes, have %d)", hdr.Length, len(data))
		}
		// Full header, but the rest of the message hasn't arrived
		// yet: ask for more data.
		return 0, nil, nil
	}

	return int(hdr.Length), data[:hdr.Length], nil
}

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

	// HandshakeComplete reports whether this connection has, as of
	// this Record, successfully decoded a BMP_MSG_INITIATION message
	// (RFC 7854 requires it to be the first message on a session).
	// It is true for the Initiation record itself and every record
	// after it on the same connection; it is false for any record
	// received before that (which, per RFC 7854, is a peer not
	// following the spec) and stays false for the life of the
	// connection if Initiation is never seen.
	//
	// Callers that turn RouterAddr into a metric label (or any other
	// unbounded-cardinality dimension) should gate on this: an
	// un-handshaked connection is exactly what an incidental TCP
	// connect (e.g. a port scan) looks like, and without this signal
	// every such probe mints its own metric series forever. See
	// README.md "Open questions".
	HandshakeComplete bool

	// PeerHeader is the decoded per-peer identity for message types
	// that carry one (all types except Initiation/Termination, per
	// RFC 7854 §4.1). It is the zero value for those two types.
	PeerHeader bmp.BMPPeerHeader

	// Message is the fully decoded BMP message: Header + PeerHeader +
	// a type-specific Body (one of bmp.BMPRouteMonitoring,
	// BMPStatisticsReport, BMPPeerUpNotification,
	// BMPPeerDownNotification, BMPInitiation, BMPTermination,
	// BMPRouteMirroring).
	//
	// Message.Body may be incompletely populated when this Record was
	// forwarded despite a non-nil decode error (see serveConn):
	// gobgp's ParseBMPMessage can return a non-nil *BMPMessage with a
	// fully decoded Header/PeerHeader alongside an error from parsing
	// an inner BGP attribute it doesn't understand. Check the
	// corresponding ErrorCallback invocation (correlated by
	// RouterAddr and time) if you need to know whether this Record's
	// Body fully decoded.
	Message *bmp.BMPMessage

	// Raw holds the original wire bytes for this one message, for
	// reprocessing, debugging, or re-decoding with different options.
	// It is a copy; callers may retain it safely.
	Raw []byte
}

// Callback is invoked once per successfully decoded BMP message. It runs
// on the per-connection goroutine that received the message, so it must
// not block for long and must not call back into the Collector.
//
// A panic inside Callback is recovered by the Collector (logged, and
// reported via ErrorCallback if set) rather than propagating: a bad
// callback on one connection must not crash the whole process and take
// every other in-flight router connection down with it.
type Callback func(Record)

// ErrorCallback is invoked once per per-connection error (decode failure
// or I/O error) that terminates that connection's read loop. It is
// optional; if nil, errors are only logged.
//
// Like Callback, a panic inside ErrorCallback is recovered rather than
// propagated.
type ErrorCallback func(routerAddr net.Addr, err error)

// Collector is a BMP monitoring station: it listens for inbound TCP
// connections from routers acting as BMP clients (RFC 7854 -- BMP is
// always initiated by the monitored router, dialing out to the
// collector), and decodes every BMP message on every connection.
//
// The zero value is not usable; construct with New.
type Collector struct {
	listenAddr      string
	onRecord        Callback
	onError         ErrorCallback
	logger          *slog.Logger
	maxConns        int
	idleTimeout     time.Duration
	keepAlivePeriod time.Duration

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

// WithMaxConnections caps the number of router connections this
// Collector will accept concurrently. Once the cap is reached, new
// connections are accepted (to avoid leaving the peer's SYN hanging) and
// then immediately closed, so a connection flood can't exhaust file
// descriptors or goroutines. n <= 0 disables the cap (unlimited).
func WithMaxConnections(n int) Option {
	return func(c *Collector) { c.maxConns = n }
}

// WithIdleTimeout sets how long a connection may go without any data
// being read from it before it is closed. Every Read on the connection
// refreshes the deadline, so this bounds idle time, not total session
// duration. d <= 0 disables the idle timeout.
func WithIdleTimeout(d time.Duration) Option {
	return func(c *Collector) { c.idleTimeout = d }
}

// WithTCPKeepAlive enables OS-level TCP keepalive probes on every
// accepted connection with the given probe period. period <= 0 disables
// keepalive entirely.
func WithTCPKeepAlive(period time.Duration) Option {
	return func(c *Collector) { c.keepAlivePeriod = period }
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
		listenAddr:      listenAddr,
		onRecord:        cb,
		logger:          slog.Default(),
		conns:           make(map[net.Conn]struct{}),
		maxConns:        defaultMaxConnections,
		idleTimeout:     defaultIdleTimeout,
		keepAlivePeriod: defaultKeepAlivePeriod,
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

// isTransientAcceptError reports whether err from a failed Accept is
// likely recoverable (e.g. transient resource exhaustion such as
// EMFILE/ENFILE, or a configured accept deadline expiring) rather than a
// fatal listener-level failure that will never clear. net.Error's
// Temporary method is deprecated upstream with no single static
// replacement covering every case it used to (see the net package's own
// docs), but it remains the only portable signal for this, so it is
// still checked here alongside Timeout.
func isTransientAcceptError(err error) bool {
	var ne net.Error
	if !errors.As(err, &ne) {
		return false
	}
	if ne.Timeout() {
		return true
	}
	//nolint:staticcheck // SA1019: no replacement covers this case; see comment above.
	return ne.Temporary()
}

func (c *Collector) acceptLoop(ctx context.Context, ln net.Listener) {
	defer c.wg.Done()

	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				// Expected shutdown path: the listener was
				// closed on purpose. Not an error worth
				// logging as such.
				return
			}

			if isTransientAcceptError(err) {
				// A transient Accept() failure (e.g. the
				// process is briefly out of file
				// descriptors) must not permanently stop
				// the accept loop for the rest of the
				// process's life -- log and keep accepting,
				// with a small increasing backoff so a
				// sustained transient condition doesn't spin
				// the loop at 100% CPU while it clears.
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else if backoff < time.Second {
					backoff *= 2
				}
				c.logger.Warn("bmpcollector: transient accept error, continuing", "err", err, "backoff", backoff)
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return
				}
				continue
			}

			c.logger.Error("bmpcollector: accept failed, stopping accept loop", "err", err)
			return
		}
		backoff = 0

		if tc, ok := conn.(*net.TCPConn); ok && c.keepAlivePeriod > 0 {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(c.keepAlivePeriod)
		}

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = conn.Close()
			return
		}
		if c.maxConns > 0 && len(c.conns) >= c.maxConns {
			c.mu.Unlock()
			c.logger.Warn("bmpcollector: max concurrent connections reached, rejecting connection",
				"addr", conn.RemoteAddr(), "max", c.maxConns)
			_ = conn.Close()
			continue
		}
		c.conns[conn] = struct{}{}
		c.mu.Unlock()

		c.wg.Add(1)
		go c.serveConn(ctx, conn)
	}
}

// idleTimeoutConn wraps a net.Conn so every Read refreshes a
// SetReadDeadline for timeout, giving the connection a hard idle
// timeout. bufio.Scanner (and anything else reading from the
// connection) has no hook for "run this before each Read", so the
// deadline has to be applied at the Read call itself; embedding net.Conn
// lets every other method (Close, RemoteAddr, ...) pass through
// unchanged.
type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleTimeoutConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// safeInvokeCallback calls fn and recovers any panic, logging it (and,
// if c.onError is set, reporting it through c.onError -- itself guarded
// against panicking too) instead of letting it propagate. A single misbehaving
// caller-supplied callback (e.g. unguarded field access on a message
// type it didn't expect) must not crash the whole process and take
// every other in-flight router connection down with it.
func (c *Collector) safeInvokeCallback(remote net.Addr, what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			c.logger.Error("bmpcollector: recovered panic in "+what,
				"addr", remote, "panic", r, "stack", string(stack))
			if c.onError != nil {
				c.safeInvokeErrorCallback(remote, fmt.Errorf("bmpcollector: %s panicked: %v", what, r))
			}
		}
	}()
	fn()
}

// safeInvokeErrorCallback calls c.onError, recovering (and merely
// logging) any panic from it -- the error callback itself must not be
// able to take the process down either.
func (c *Collector) safeInvokeErrorCallback(remote net.Addr, err error) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("bmpcollector: recovered panic in error callback", "addr", remote, "panic", r)
		}
	}()
	c.onError(remote, err)
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
	// The idle timeout below is a second, independent way out: a
	// connection that never sends anything (or stalls mid-message)
	// gets closed on its own without waiting for Shutdown at all.
	scanner := bufio.NewScanner(&idleTimeoutConn{Conn: conn, timeout: c.idleTimeout})
	scanner.Buffer(make([]byte, 4096), maxBMPMessageSize)
	scanner.Split(splitBMPMessage)

	// handshakeComplete tracks, per RFC 7854 §4.1, whether this
	// connection has produced a successfully-decoded Initiation
	// message yet (Initiation must be the first message on a
	// session). Callers use Record.HandshakeComplete to decide
	// whether RouterAddr is safe to use as an unbounded-cardinality
	// metric label -- see that field's doc comment and README.md.
	var handshakeComplete bool

	for scanner.Scan() {
		raw := append([]byte(nil), scanner.Bytes()...) // copy: Scanner reuses its buffer
		msg, err := bmp.ParseBMPMessage(raw)
		if err != nil {
			c.logger.Warn("bmpcollector: failed to decode BMP message", "addr", remote.String(), "err", err)
			if c.onError != nil {
				c.safeInvokeErrorCallback(remote, fmt.Errorf("decode: %w", err))
			}
			if msg == nil {
				// Nothing usable came out of this message at
				// all (header itself didn't decode, or a
				// non-route-monitoring body failed outright
				// with no partial result). Nothing to
				// forward.
				continue
			}
			// gobgp's ParseBMPMessage can return a non-nil
			// *BMPMessage alongside a non-nil error for a
			// BMP_MSG_ROUTE_MONITORING message whose inner BGP
			// UPDATE has an attribute it can't parse (confirmed
			// against real vendor-gear-like input, not just
			// gobgp's own encoder) -- in that case Header and
			// PeerHeader are already fully decoded even though
			// Body's decode failed. Previously this whole
			// record -- including the peer identity -- was
			// dropped via a blanket "continue". Fall through and
			// forward what did decode instead of discarding it.
		}

		if msg.Header.Type == bmp.BMP_MSG_INITIATION {
			handshakeComplete = true
		}

		rec := Record{
			ReceivedAt:        time.Now(),
			RouterAddr:        remote,
			HandshakeComplete: handshakeComplete,
			PeerHeader:        msg.PeerHeader,
			Message:           msg,
			Raw:               raw,
		}
		c.safeInvokeCallback(remote, "message callback", func() {
			c.onRecord(rec)
		})
	}

	if err := scanner.Err(); err != nil {
		c.logger.Warn("bmpcollector: connection read error", "addr", remote.String(), "err", err)
		if c.onError != nil {
			c.safeInvokeErrorCallback(remote, fmt.Errorf("read: %w", err))
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
