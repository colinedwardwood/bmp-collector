// Package bmpcollector implements a minimal BMP (BGP Monitoring Protocol,
// RFC 7854) collector: it accepts inbound TCP connections from routers,
// frames and decodes BMP messages, and hands decoded records to a
// caller-supplied callback.
//
// See README.md "Status" and "Open questions" for what has (CI, fuzzing,
// Docker, decode coverage for all 7 RFC 7854 message types) and has not
// (real-router validation, transport security) been verified as of this
// writing.
//
// The wire-format decoding (BMP envelope + inner BGP UPDATE) is not
// reimplemented here. It is delegated entirely to
// github.com/osrg/gobgp/v3/pkg/packet/bmp (and its bgp sub-package),
// which already implements the full RFC 7854 message set and exposes a
// bufio.SplitFunc (bmp.SplitBMP) for framing a raw TCP byte stream into
// discrete messages. This package only adds the TCP accept/serve
// lifecycle and a Start(ctx)/Shutdown(ctx)-shaped API around it -- plus,
// as of this revision, its own framing validation layered on top of
// gobgp's decoder (see decodeAndValidateBMPHeader, applied by both
// splitBMPMessage -- kept as a directly tested/fuzzed bufio.SplitFunc --
// and readOneBMPMessage, what serveConn actually reads a connection
// with) because gobgp's own bmp.SplitBMP does not safely handle every
// malformed-header case a hostile or buggy peer can send (see the fix
// notes on splitBMPMessage).
package bmpcollector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
	"golang.org/x/sync/semaphore"
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

	// defaultMaxBufferedBytes caps the aggregate number of bytes this
	// Collector will allow to be buffered, in total and at once, across
	// every connection's currently in-flight message.
	//
	// CRITICAL fix: maxConns (defaultMaxConnections) and
	// maxBMPMessageSize are each a reasonable, independently-enforced
	// bound -- but their PRODUCT is not. ~100-150 ordinary, individually
	// spec-compliant connections (well under maxConns) each sending one
	// ~900KB message (well under maxBMPMessageSize) can make this
	// collector buffer well over 100MB concurrently, with no single
	// connection or message ever exceeding its own cap. Reproduced
	// against the unpatched code: ~100-150 concurrent connections each
	// sending one ~900KB message OOM-kills a container limited to 64MB.
	//
	// This budget is the fix: readOneBMPMessage requires every in-flight
	// message to acquire its declared Length from this collector-wide
	// semaphore before allocating or reading any of its body, and
	// serveConn releases it once that message has been fully decoded
	// and handed to the callback (or the connection tears down with one
	// still pending). That bounds total buffered bytes by this constant
	// regardless of how many connections are open -- admission control,
	// not a per-connection or per-message limit. It also, deliberately,
	// bounds *steady-state* memory, not just the rate new buffering can
	// start: each message is read into a fresh, message-sized buffer
	// that becomes collectible the moment that message is done, rather
	// than a per-connection buffer that only ever grows (see
	// readOneBMPMessage's doc comment for why that distinction mattered
	// in practice for this specific fix).
	defaultMaxBufferedBytes = 64 << 20 // 64 MiB
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

	hdr, err := decodeAndValidateBMPHeader(data[:bmpHeaderSize])
	if err != nil {
		return 0, nil, err
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

// decodeAndValidateBMPHeader decodes exactly bmpHeaderSize bytes as a
// BMP header and applies this package's own validation beyond gobgp's
// bare version-byte check -- Length must be large enough to cover the
// header itself and no larger than maxBMPMessageSize (see
// splitBMPMessage's doc comment for the two CRITICAL framing bugs this
// guards against). Shared by splitBMPMessage (a bufio.SplitFunc, tested
// and fuzzed directly against that exact contract) and serveConn's
// per-message read loop (see readOneBMPMessage), so the two paths can't
// validate a header differently from each other.
func decodeAndValidateBMPHeader(hdrBytes []byte) (*bmp.BMPHeader, error) {
	hdr := &bmp.BMPHeader{}
	if decodeErr := hdr.DecodeFromBytes(hdrBytes); decodeErr != nil {
		// gobgp only returns an error here for an unrecognized
		// version byte (see BMPHeader.DecodeFromBytes). Reject the
		// connection rather than waiting on an already-poisoned
		// buffer for more data that can never produce a valid
		// token.
		return nil, fmt.Errorf("%w: %w", errInvalidBMPHeader, decodeErr)
	}

	// gobgp's BMPHeader.DecodeFromBytes only validates Version; it
	// does not check that Length is large enough to even contain the
	// 6-byte header it was just decoded from. Enforce that ourselves
	// -- this is the fix for the Length=0 busy-loop described on
	// splitBMPMessage.
	if hdr.Length < uint32(bmpHeaderSize) {
		return nil, fmt.Errorf("%w: length=%d is smaller than the %d-byte header", errInvalidBMPHeader, hdr.Length, bmpHeaderSize)
	}
	if hdr.Length > uint32(maxBMPMessageSize) {
		return nil, fmt.Errorf("%w: length=%d exceeds max message size %d", errInvalidBMPHeader, hdr.Length, maxBMPMessageSize)
	}
	return hdr, nil
}

// parseBMPMessagePreservingPartial decodes one BMP message the same way
// gobgp's own bmp.ParseBMPMessage does, with one deliberate difference.
//
// gobgp's (unexported, so it can't be called or wrapped directly)
// parseBMPMessage returns (nil, err) for every message type EXCEPT
// BMP_MSG_ROUTE_MONITORING when the type-specific Body fails to parse --
// discarding the Header and PeerHeader that had, in every case, already
// decoded successfully by that point. That is a full-record-loss bug for
// StatisticsReport, PeerUpNotification, PeerDownNotification, and
// RouteMirroring: a body gobgp's decoder can't fully parse silently
// drops the peer identity that *did* decode, the same bug class
// RouteMonitoring alone was special-cased against upstream. This
// function generalizes that fix to every message type by reimplementing
// the same decode sequence (using only gobgp's exported pieces --
// BMPHeader/BMPPeerHeader.DecodeFromBytes, BMPBody.ParseBody) and always
// returning the partially-or-fully decoded *bmp.BMPMessage alongside any
// error, regardless of type, so the caller (serveConn) can forward
// whatever peer-identity/header information did decode instead of
// discarding the whole record.
//
// It also restores the panic recovery bmp.ParseBMPMessage has internally
// (gobgp's own parseBMPMessage wraps its body in a deferred recover):
// reimplementing the decode with exported calls steps outside that
// internal recover, and this function decodes fully untrusted wire
// bytes, so it needs its own -- following this package's existing
// safeInvokeCallback/safeInvokeErrorCallback recover-and-report pattern
// rather than inventing a new one.
func parseBMPMessagePreservingPartial(data []byte) (msg *bmp.BMPMessage, err error) {
	defer func() {
		if r := recover(); r != nil {
			msg = nil
			err = fmt.Errorf("bmpcollector: panic parsing BMP message: %v", r)
		}
	}()

	msg = &bmp.BMPMessage{}
	if err = msg.Header.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	body := data[bmpHeaderSize:msg.Header.Length]

	switch msg.Header.Type {
	case bmp.BMP_MSG_ROUTE_MONITORING:
		msg.Body = &bmp.BMPRouteMonitoring{}
	case bmp.BMP_MSG_STATISTICS_REPORT:
		msg.Body = &bmp.BMPStatisticsReport{}
	case bmp.BMP_MSG_PEER_DOWN_NOTIFICATION:
		msg.Body = &bmp.BMPPeerDownNotification{}
	case bmp.BMP_MSG_PEER_UP_NOTIFICATION:
		msg.Body = &bmp.BMPPeerUpNotification{}
	case bmp.BMP_MSG_INITIATION:
		msg.Body = &bmp.BMPInitiation{}
	case bmp.BMP_MSG_TERMINATION:
		msg.Body = &bmp.BMPTermination{}
	case bmp.BMP_MSG_ROUTE_MIRRORING:
		msg.Body = &bmp.BMPRouteMirroring{}
	default:
		return nil, fmt.Errorf("bmpcollector: unsupported BMP message type: %d", msg.Header.Type)
	}

	if msg.Header.Type != bmp.BMP_MSG_INITIATION && msg.Header.Type != bmp.BMP_MSG_TERMINATION {
		if perr := msg.PeerHeader.DecodeFromBytes(body); perr != nil {
			// gobgp's BMPPeerHeader.DecodeFromBytes never actually
			// returns a non-nil error today (it's a fixed 42-byte
			// decode), but msg.Header is still fully decoded and
			// usable even if that were ever to change -- forward it
			// rather than assume this branch is unreachable forever.
			return msg, perr
		}
		body = body[bmp.BMP_PEER_HEADER_SIZE:]
	}

	if err = msg.Body.ParseBody(msg, body); err != nil {
		// The fix: always forward msg here. Header and (for every type
		// except Initiation/Termination) PeerHeader are already fully
		// decoded at this point no matter which message type this is,
		// regardless of whether Body's decode itself succeeded.
		return msg, err
	}

	return msg, nil
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
	// forwarded despite a non-nil decode error (see serveConn and
	// parseBMPMessagePreservingPartial): a message of any RFC 7854 type
	// whose type-specific Body fails to parse still forwards Header and
	// PeerHeader, which decode independently of Body and have, in
	// practice, already succeeded by that point. Check the
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
// handshakeComplete mirrors Record.HandshakeComplete exactly: true once
// this connection has successfully decoded a BMP_MSG_INITIATION message,
// false for any error before that. Cardinality-bug fix: callers that
// turn routerAddr into a metric label (or any other unbounded-cardinality
// dimension) must gate on handshakeComplete the same way
// Record.HandshakeComplete already requires onRecord to -- an
// un-handshaked connection is exactly what a port scan or stray TCP
// connect looks like, and without this signal every such probe mints its
// own metric series forever, here just as much as in onRecord. Before
// this field existed, ErrorCallback gave callers no way to apply that
// same gate at all.
//
// Like Callback, a panic inside ErrorCallback is recovered rather than
// propagated.
type ErrorCallback func(routerAddr net.Addr, handshakeComplete bool, err error)

// Collector is a BMP monitoring station: it listens for inbound TCP
// connections from routers acting as BMP clients (RFC 7854 -- BMP is
// always initiated by the monitored router, dialing out to the
// collector), and decodes every BMP message on every connection.
//
// The zero value is not usable; construct with New.
type Collector struct {
	listenAddr       string
	onRecord         Callback
	onError          ErrorCallback
	logger           *slog.Logger
	maxConns         int
	idleTimeout      time.Duration
	keepAlivePeriod  time.Duration
	maxBufferedBytes int64
	bufSem           *semaphore.Weighted

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]context.CancelFunc
	wg       sync.WaitGroup
	started  bool
	closed   bool

	// shutdownCh and shutdownOnce let Shutdown wake Start's ctx-watcher
	// goroutine (see Start) even when the caller's ctx is never
	// cancelled -- the common case, and the one every test in this
	// package uses (ctx is cancelled only via a deferred cleanup that
	// runs after Shutdown has already returned). Without this signal,
	// tracking that goroutine in wg (the goroutine-leak fix) would make
	// Shutdown itself hang forever waiting on a goroutine that only
	// wakes on ctx.Done().
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
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

// WithMaxBufferedBytes caps the aggregate number of bytes this Collector
// will buffer, in total and at once, across every connection's
// currently in-flight message (see defaultMaxBufferedBytes for the full
// rationale -- this is the fix for the aggregate-memory/OOM bug: per-
// connection and per-message caps are each insufficient alone since
// their product is unbounded). n <= 0 disables the budget entirely
// (unlimited) -- do this only if an equivalent limit is enforced some
// other way (e.g. a container memory limit the operator has already
// sized for worst-case conns*maxMessageSize), since disabling it
// reintroduces the unbounded-aggregate-memory condition this option
// exists to close off.
func WithMaxBufferedBytes(n int64) Option {
	return func(c *Collector) { c.maxBufferedBytes = n }
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
		listenAddr:       listenAddr,
		onRecord:         cb,
		logger:           slog.Default(),
		conns:            make(map[net.Conn]context.CancelFunc),
		shutdownCh:       make(chan struct{}),
		maxConns:         defaultMaxConnections,
		idleTimeout:      defaultIdleTimeout,
		keepAlivePeriod:  defaultKeepAlivePeriod,
		maxBufferedBytes: defaultMaxBufferedBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.maxBufferedBytes > 0 {
		// A budget smaller than the largest single message this
		// Collector will ever accept would mean that message could
		// never be admitted (semaphore.Weighted.Acquire blocks forever
		// on a request larger than the semaphore's own size, only
		// returning once ctx is done) -- clamp rather than let a
		// too-small WithMaxBufferedBytes value silently wedge every
		// connection that happens to receive one max-size message.
		if c.maxBufferedBytes < int64(maxBMPMessageSize) {
			c.maxBufferedBytes = int64(maxBMPMessageSize)
		}
		c.bufSem = semaphore.NewWeighted(c.maxBufferedBytes)
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
	//
	// Goroutine-leak fix: this watcher must be tracked in c.wg like
	// every other goroutine this Collector spawns. Before this fix it
	// wasn't, so for any caller that invokes Start with a context that
	// is never cancelled (common: context.Background()), this goroutine
	// parked on <-ctx.Done() forever -- Shutdown waits on c.wg, which
	// never counted this goroutine, so Shutdown reported success while
	// this goroutine leaked for the life of the process. Reproduced: the
	// count of such leaked goroutines grew by one per Start call with no
	// corresponding decrease on Shutdown (see
	// TestCollector_StartShutdownCycles_DoNotLeakGoroutines).
	//
	// Simply adding it to c.wg is not sufficient by itself, though: that
	// would make Shutdown hang waiting on this goroutine for exactly the
	// same "ctx never cancelled" case this fix targets, since Shutdown
	// itself doesn't cancel ctx (by design -- a caller may legitimately
	// call Shutdown while ctx is still live). shutdownCh is what makes
	// both true at once: this goroutine is reliably accounted for in
	// c.wg, AND Shutdown can always make it exit promptly by closing
	// shutdownCh, with or without ctx ever being cancelled.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		select {
		case <-ctx.Done():
		case <-c.shutdownCh:
		}
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
		// Each connection gets its own child context, cancelled when
		// this specific connection tears down (serveConn's deferred
		// cleanup) or when Shutdown explicitly closes it -- not only
		// when the whole Collector's ctx is done. readOneBMPMessage's
		// sem.Acquire call (the aggregate buffer-budget fix) uses this
		// to bound how long it will wait for budget to a single
		// connection's lifetime, so Shutdown can unblock a connection
		// parked waiting on that budget the same way it already
		// unblocks one parked in Read (via conn.Close()): without a
		// per-connection cancel, only the Collector-wide ctx could ever
		// wake such a wait.
		connCtx, cancel := context.WithCancel(ctx)

		c.conns[conn] = cancel
		c.mu.Unlock()

		c.wg.Add(1)
		go c.serveConn(connCtx, conn)
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
		if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
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
func (c *Collector) safeInvokeCallback(remote net.Addr, handshakeComplete bool, what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			c.logger.Error("bmpcollector: recovered panic in "+what,
				"addr", remote, "panic", r, "stack", string(stack))
			if c.onError != nil {
				c.safeInvokeErrorCallback(remote, handshakeComplete, fmt.Errorf("bmpcollector: %s panicked: %v", what, r))
			}
		}
	}()
	fn()
}

// safeInvokeErrorCallback calls c.onError, recovering (and merely
// logging) any panic from it -- the error callback itself must not be
// able to take the process down either.
func (c *Collector) safeInvokeErrorCallback(remote net.Addr, handshakeComplete bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("bmpcollector: recovered panic in error callback", "addr", remote, "panic", r)
		}
	}()
	c.onError(remote, handshakeComplete, err)
}

func (c *Collector) serveConn(ctx context.Context, conn net.Conn) {
	defer c.wg.Done()
	defer func() {
		c.mu.Lock()
		if cancel, ok := c.conns[conn]; ok {
			cancel()
		}
		delete(c.conns, conn)
		c.mu.Unlock()
		_ = conn.Close()
	}()

	remote := conn.RemoteAddr()
	c.logger.Info("bmpcollector: router connected", "addr", remote.String())

	// Closing the connection is the only way to unblock a goroutine
	// that's blocked in Read once Shutdown/ctx-done wants out; that
	// happens via Shutdown's/ctx-watcher's conn.Close() calls, which
	// make the read below return an error and the loop exit. The idle
	// timeout below is a second, independent way out: a connection that
	// never sends anything (or stalls mid-message) gets closed on its
	// own without waiting for Shutdown at all.
	//
	// r is deliberately a small, fixed-size bufio.Reader -- NOT a
	// bufio.Scanner buffering whole messages. See readOneBMPMessage's
	// doc comment for why: a Scanner's internal buffer only ever grows,
	// never shrinks, so if this were still Scanner-based, any
	// connection that ever received one large message would permanently
	// retain that much capacity for the rest of its (possibly
	// indefinite, per RFC 7854's long-lived BMP sessions) lifetime --
	// which defeats the aggregate buffer-budget fix's actual goal
	// (bounding *total* buffered bytes, not just the rate new buffering
	// can start) for exactly the many-long-lived-connections shape the
	// aggregate-memory bug was found with. readOneBMPMessage instead
	// allocates a fresh, message-sized buffer per message, which
	// becomes garbage (and collectible) the moment that one message is
	// done, regardless of how long the connection itself stays open.
	r := bufio.NewReaderSize(&idleTimeoutConn{Conn: conn, timeout: c.idleTimeout}, 4096)

	// handshakeComplete tracks, per RFC 7854 §4.1, whether this
	// connection has produced a successfully-decoded Initiation
	// message yet (Initiation must be the first message on a
	// session). Callers use Record.HandshakeComplete (and, for errors,
	// ErrorCallback's handshakeComplete parameter) to decide whether
	// RouterAddr is safe to use as an unbounded-cardinality metric
	// label -- see that field's doc comment and README.md.
	var handshakeComplete bool

	for {
		raw, cleanEOF, err := readOneBMPMessage(ctx, r, c.bufSem)
		if cleanEOF {
			// Ordinary end of a connection at a message boundary --
			// not an error worth reporting, same as the old
			// Scanner-based loop ending with scanner.Err() == nil.
			break
		}
		if err != nil {
			c.logger.Warn("bmpcollector: connection read error", "addr", remote.String(), "err", err)
			if c.onError != nil {
				c.safeInvokeErrorCallback(remote, handshakeComplete, err)
			}
			break
		}

		// This closure's extent is deliberately exactly this one
		// message's processing, from decode through the callback
		// returning: the aggregate-memory fix's budget reservation
		// readOneBMPMessage acquired for exactly len(raw) bytes must
		// be released once, after this, however this iteration exits
		// (successfully forwarded, an early return for a
		// non-forwardable decode failure, or a panic recovered inside
		// the callback itself) -- releasing any earlier (e.g. right
		// after the bytes were read, before this processing) would
		// leave that processing itself unbounded by the budget, which
		// is the mistake an earlier version of this fix made (see
		// readOneBMPMessage's doc comment).
		func() {
			if c.bufSem != nil {
				defer c.bufSem.Release(int64(len(raw)))
			}

			msg, decodeErr := parseBMPMessagePreservingPartial(raw)
			if decodeErr != nil {
				c.logger.Warn("bmpcollector: failed to decode BMP message", "addr", remote.String(), "err", decodeErr)
				if c.onError != nil {
					c.safeInvokeErrorCallback(remote, handshakeComplete, fmt.Errorf("decode: %w", decodeErr))
				}
				if msg == nil {
					// Nothing usable came out of this message at
					// all (header itself didn't decode, the type
					// was unrecognized, or the parse panicked).
					// Nothing to forward.
					return
				}
				// parseBMPMessagePreservingPartial returns a non-nil
				// *bmp.BMPMessage alongside a non-nil error whenever
				// Header (and, for types that carry one, PeerHeader)
				// decoded successfully even though the type-specific
				// Body's decode failed -- for every RFC 7854 message
				// type, not just RouteMonitoring (see that function's
				// doc comment for why only RouteMonitoring used to get
				// this treatment, from gobgp's own decoder). Fall
				// through and forward what did decode instead of
				// discarding the whole record, peer identity included.
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
			c.safeInvokeCallback(remote, handshakeComplete, "message callback", func() {
				c.onRecord(rec)
			})
		}()
	}

	c.logger.Info("bmpcollector: router disconnected", "addr", remote.String())
}

// readOneBMPMessage reads exactly one framed BMP message from r: a
// 6-byte header (validated via decodeAndValidateBMPHeader, the same
// rules splitBMPMessage applies), then exactly Length-6 more bytes for
// the body, returned together as one newly-allocated []byte covering
// the whole message.
//
// This -- not a bufio.Scanner over splitBMPMessage -- is what serveConn
// actually uses to read a connection, specifically so that no
// connection-lifetime object ever retains a buffer sized to the largest
// message that connection has ever received: see serveConn's doc
// comment for why that matters for the aggregate buffer-budget fix. The
// returned slice is an ordinary local value with no owner beyond the
// caller's current iteration, so it becomes collectible the moment the
// caller is done with it, no matter how long the connection itself
// remains open afterward.
//
// If sem is non-nil, this acquires the message's declared Length from
// it (bounded by ctx) before allocating or reading the body -- the
// aggregate-memory fix's admission control (see defaultMaxBufferedBytes).
// The caller must release that reservation (bmpSem.Release, with the
// same Length) once it is actually done with the returned message
// (decoded and handed to the callback), not merely once the bytes are
// read; serveConn does this by deferring the release across its own
// per-message processing, mirroring this function's acquire.
//
// Returns (nil, true, nil) for a clean end-of-connection exactly at a
// message boundary (not an error). Returns (nil, false, err) for every
// other failure: a truncated header or body, an ordinary read/idle-
// timeout error, an invalid header (errInvalidBMPHeader), or ctx being
// done while waiting on sem. On success, returns (raw, false, nil) with
// the semaphore reservation (if any) still held -- release is the
// caller's responsibility, exactly once, via sem.Release(ctx-independent,
// len(raw)) once it is truly done with raw.
func readOneBMPMessage(ctx context.Context, r *bufio.Reader, sem *semaphore.Weighted) (raw []byte, cleanEOF bool, err error) {
	hdrBuf := make([]byte, bmpHeaderSize)
	n, err := io.ReadFull(r, hdrBuf)
	if err != nil {
		if errors.Is(err, io.EOF) && n == 0 {
			return nil, true, nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, fmt.Errorf("bmpcollector: connection closed with a truncated BMP header (%d of %d bytes)", n, bmpHeaderSize)
		}
		return nil, false, fmt.Errorf("bmpcollector: read: %w", err)
	}

	hdr, err := decodeAndValidateBMPHeader(hdrBuf)
	if err != nil {
		return nil, false, err
	}

	if sem != nil {
		if acquireErr := sem.Acquire(ctx, int64(hdr.Length)); acquireErr != nil {
			return nil, false, fmt.Errorf("bmpcollector: waiting for connection buffer budget: %w", acquireErr)
		}
	}

	raw = make([]byte, hdr.Length)
	copy(raw, hdrBuf)
	if hdr.Length > uint32(bmpHeaderSize) {
		if _, err := io.ReadFull(r, raw[bmpHeaderSize:]); err != nil {
			if sem != nil {
				sem.Release(int64(hdr.Length))
			}
			return nil, false, fmt.Errorf("bmpcollector: connection closed mid-message (want %d bytes): %w", hdr.Length, err)
		}
	}
	return raw, false, nil
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
	// Wake Start's ctx-watcher goroutine even if the caller's ctx is
	// never cancelled -- see shutdownCh's doc comment on the Collector
	// struct and the goroutine-leak fix notes in Start.
	c.shutdownOnce.Do(func() { close(c.shutdownCh) })
	_ = c.closeListener()

	c.mu.Lock()
	conns := make([]net.Conn, 0, len(c.conns))
	cancels := make([]context.CancelFunc, 0, len(c.conns))
	for conn, cancel := range c.conns {
		conns = append(conns, conn)
		cancels = append(cancels, cancel)
	}
	c.mu.Unlock()

	// Cancel each connection's own context first: this is what
	// unblocks a serveConn goroutine currently parked waiting on the
	// aggregate buffer-budget semaphore (readOneBMPMessage's
	// sem.Acquire), which -- unlike a blocked Read -- conn.Close()
	// alone cannot interrupt. Then close the connections, which
	// unblocks a serveConn goroutine blocked in Read the way it always
	// has.
	for _, cancel := range cancels {
		cancel()
	}
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
