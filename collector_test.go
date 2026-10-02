package bmpcollector

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// buildSyntheticRouteMonitoring constructs a BMP RouteMonitoring message
// exactly the way a router would (peer header + an inner BGP UPDATE with
// NLRI/AS-path/next-hop attributes), using gobgp's own constructors, and
// returns its serialized wire bytes.
//
// NOTE (see README.md "Open questions"): this is a self-serialize/
// self-parse round trip against gobgp's own encoder, which cannot by
// itself catch discrepancies between that encoder and how real routers
// (Cisco/Juniper/Arista) encode BMP on the wire. It proves the
// Collector's TCP-framing/decode wiring is correct; it does not by
// itself prove interop with real hardware.
func buildSyntheticRouteMonitoring(t testing.TB) []byte {
	t.Helper()

	nlri := bgp.NewIPAddrPrefix(24, "203.0.113.0")
	pathAttrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0), // IGP
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65002}),
		}),
		bgp.NewPathAttributeNextHop("192.0.2.1"),
	}
	update := bgp.NewBGPUpdateMessage(nil, pathAttrs, []*bgp.IPAddrPrefix{nlri})

	peerHeader := bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_GLOBAL,
		0, // flags: pre-policy, IPv4
		0, // route distinguisher
		"198.51.100.1",
		65010,
		"198.51.100.1",
		1758700000.0,
	)
	bmpMsg := bmp.NewBMPRouteMonitoring(*peerHeader, update)

	wire, err := bmpMsg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic BMP message: %v", err)
	}
	return wire
}

// TestCollector_DecodesRouteMonitoringOverTCP is the "real decode" test:
// it starts a Collector listening on a real loopback TCP port, dials in
// as a router would, writes two back-to-back serialized BMP messages in
// a single Write (to exercise bmp.SplitBMP's stream-framing, not just
// ParseBMPMessage on one pre-cut buffer), and asserts the callback
// receives both, fully decoded, with the inner BGP UPDATE readable via
// the ordinary gobgp bgp package API.
func TestCollector_DecodesRouteMonitoringOverTCP(t *testing.T) {
	wire := buildSyntheticRouteMonitoring(t)

	var (
		mu      sync.Mutex
		records []Record
	)
	done := make(chan struct{}, 2)

	c := New("127.0.0.1:0", func(r Record) {
		mu.Lock()
		records = append(records, r)
		mu.Unlock()
		done <- struct{}{}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String() // test is in-package; direct field access is fine here

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial collector: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Two messages back to back, one write: proves SplitBMP framing
	// across a single read, not just a single decode call.
	if _, err := conn.Write(append(append([]byte{}, wire...), wire...)); err != nil {
		t.Fatalf("write synthetic BMP stream: %v", err)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for decoded record %d", i+1)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}

	for i, rec := range records {
		if rec.Message == nil {
			t.Fatalf("record %d: Message is nil", i)
		}
		if rec.Message.Header.Type != bmp.BMP_MSG_ROUTE_MONITORING {
			t.Fatalf("record %d: Header.Type = %d, want BMP_MSG_ROUTE_MONITORING", i, rec.Message.Header.Type)
		}
		if got := rec.PeerHeader.PeerAddress.String(); got != "198.51.100.1" {
			t.Fatalf("record %d: PeerHeader.PeerAddress = %s, want 198.51.100.1", i, got)
		}
		if rec.PeerHeader.PeerAS != 65010 {
			t.Fatalf("record %d: PeerHeader.PeerAS = %d, want 65010", i, rec.PeerHeader.PeerAS)
		}

		rm, ok := rec.Message.Body.(*bmp.BMPRouteMonitoring)
		if !ok {
			t.Fatalf("record %d: Body is %T, want *bmp.BMPRouteMonitoring", i, rec.Message.Body)
		}
		innerUpdate, ok := rm.BGPUpdate.Body.(*bgp.BGPUpdate)
		if !ok {
			t.Fatalf("record %d: inner BGPUpdate.Body is %T, want *bgp.BGPUpdate", i, rm.BGPUpdate.Body)
		}
		if len(innerUpdate.NLRI) != 1 || innerUpdate.NLRI[0].String() != "203.0.113.0/24" {
			t.Fatalf("record %d: NLRI = %v, want [203.0.113.0/24]", i, innerUpdate.NLRI)
		}
		if len(innerUpdate.PathAttributes) != 3 {
			t.Fatalf("record %d: got %d path attributes, want 3", i, len(innerUpdate.PathAttributes))
		}
		if len(rec.Raw) == 0 {
			t.Fatalf("record %d: Raw is empty", i)
		}
	}
}

// TestCollector_ShutdownWithoutStart_DoesNotPanic guards the lifecycle
// contract at its edges: Shutdown before any connection ever arrived
// must not block or panic.
func TestCollector_ShutdownWithoutStart_DoesNotPanic(t *testing.T) {
	c := New("127.0.0.1:0", func(Record) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// dialAndShutdownWithinBound is the shared shape for the two CRITICAL
// regression tests below: dial in, write a malformed pattern, then
// assert Collector.Shutdown returns cleanly well within a bounded
// window. The ctx timeout passed to Shutdown is deliberately longer
// than the wall-clock bound we actually assert on, so a regression
// shows up as an assertion failure ("took too long") rather than as an
// ambiguous ctx.DeadlineExceeded that could also mean "the bound itself
// was too tight".
func dialAndShutdownWithinBound(t *testing.T, c *Collector, addr string, write []byte, bound time.Duration) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial collector: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(write); err != nil {
		t.Fatalf("write malformed pattern: %v", err)
	}

	// Give the connection's read loop a moment to actually process
	// the pattern before we start shutting down.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*bound)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown did not return cleanly: %v (elapsed %v)", err, time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > bound {
		t.Fatalf("Shutdown took %v, want <= %v", elapsed, bound)
	}
}

// TestCollector_ShutdownUnblocksAfterZeroLengthHeader is the regression
// test for CRITICAL bug #1's first half: a peer that sends a
// syntactically valid 6-byte BMP header (version=3) with Length=0 (less
// than the header's own 6 bytes) used to make gobgp's bmp.SplitBMP
// return a non-nil, zero-length token forever. bufio.Scanner treats that
// as an infinite stream of successfully-produced empty tokens: a busy
// loop that spins at ~100% CPU without ever calling Read() again, so it
// never blocks in a syscall that Shutdown's conn.Close() could
// interrupt. Confirmed against the unpatched collector.go: Shutdown
// with a 3s deadline returned context.DeadlineExceeded after emitting
// over two million "failed to decode" log lines in that window.
//
// With the fix (splitBMPMessage explicitly requires Length >=
// bmpHeaderSize and rejects the connection otherwise), Shutdown must
// return quickly and without error.
func TestCollector_ShutdownUnblocksAfterZeroLengthHeader(t *testing.T) {
	c := New("127.0.0.1:0", func(Record) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	// version=3, length=0 (invalid: smaller than the 6-byte header
	// itself), type=0. This is the exact pattern that reproduced the
	// busy loop.
	pattern := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00}
	dialAndShutdownWithinBound(t, c, addr, pattern, 3*time.Second)
}

// TestCollector_ShutdownUnblocksAfterInvalidVersion is the regression
// test for CRITICAL bug #1's second half: a peer that sends a header
// whose version byte gobgp doesn't recognize used to make gobgp's
// bmp.SplitBMP return (advance=0, token=nil, err=nil) forever -- read as
// "need more data" by bufio.Scanner, but because the poisoned byte at
// the front of the buffer was never skipped, the connection would never
// produce another token again even after further, well-formed bytes
// arrived: a permanent, silent block. Confirmed against the unpatched
// collector.go: a valid message written immediately after one bad
// version byte was never delivered to the callback.
//
// With the fix, an invalid version byte is rejected outright (the
// connection is torn down) instead of silently starved, so Shutdown
// must return quickly and without error.
func TestCollector_ShutdownUnblocksAfterInvalidVersion(t *testing.T) {
	c := New("127.0.0.1:0", func(Record) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	wire := buildSyntheticRouteMonitoring(t)
	pattern := append([]byte{0x63}, wire...) // 0x63: not BMP_VERSION (3)
	dialAndShutdownWithinBound(t, c, addr, pattern, 3*time.Second)
}

// TestCollector_InvalidBMPHeader_RejectsConnectionAndReportsError checks
// the observable behavior splitBMPMessage is responsible for beyond
// just unblocking Shutdown (the two tests above): a connection sent a
// bad header should be actively torn down and reported through
// ErrorCallback, not merely left to be caught by the next Shutdown.
func TestCollector_InvalidBMPHeader_RejectsConnectionAndReportsError(t *testing.T) {
	var (
		mu       sync.Mutex
		gotErrs  []error
		gotAddrs []net.Addr
	)
	c := New("127.0.0.1:0", func(Record) {}, WithErrorCallback(func(addr net.Addr, handshakeComplete bool, err error) {
		mu.Lock()
		defer mu.Unlock()
		gotErrs = append(gotErrs, err)
		gotAddrs = append(gotAddrs, addr)
		if handshakeComplete {
			t.Errorf("handshakeComplete = true, want false (no Initiation was ever sent on this connection)")
		}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The connection should be actively closed by the collector (not
	// just left dangling): a subsequent read from our side should
	// see EOF/closed within a bound, well under the old busy-loop's
	// "forever".
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("expected connection to be closed by the collector, got a successful read")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(gotErrs)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotErrs) == 0 {
		t.Fatalf("ErrorCallback was never invoked for the invalid header")
	}
	if !errors.Is(gotErrs[0], errInvalidBMPHeader) {
		t.Fatalf("error = %v, want it to wrap errInvalidBMPHeader", gotErrs[0])
	}
	if gotAddrs[0] == nil {
		t.Fatalf("ErrorCallback got a nil addr")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestCollector_PanicInCallback_DoesNotCrashProcess is the regression
// test for CRITICAL bug #2: a bad Callback (e.g. main.go's onRecord
// doing unguarded field access on a message type it didn't expect) must
// not crash the whole process and take every other in-flight
// connection down with it. Without recover(), an unrecovered panic in a
// goroutine (serveConn's) is fatal to the entire program -- this test
// would kill the whole `go test` process, not just fail, if the
// recovery were removed. It also asserts that a second, healthy
// connection served concurrently is completely unaffected by the first
// one's panicking callback.
func TestCollector_PanicInCallback_DoesNotCrashProcess(t *testing.T) {
	wire := buildSyntheticRouteMonitoring(t)

	var panicCount atomic.Int32
	var healthyRecords atomic.Int32

	c := New("127.0.0.1:0", func(r Record) {
		// Simulate main.go's onRecord doing unguarded field access
		// on a message type it didn't expect. Every record built
		// from buildSyntheticRouteMonitoring's wire has
		// PeerAS == 65010, so connection A (which sends exactly
		// that wire) always hits this branch; connection B (built
		// with a different PeerAS below) never does.
		if r.PeerHeader.PeerAS == 65010 {
			panicCount.Add(1)
			panic("bmpcollector test: simulated bad callback (unguarded field access)")
		}
		healthyRecords.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	// Connection A: will trigger the panicking branch above (its
	// PeerAS matches 65010, from buildSyntheticRouteMonitoring).
	connA, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer func() { _ = connA.Close() }()
	if _, err := connA.Write(wire); err != nil {
		t.Fatalf("write A: %v", err)
	}

	// Wait for the panic to have happened and been recovered.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && panicCount.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if panicCount.Load() == 0 {
		t.Fatalf("panicking callback never ran (or the recovered panic path was never reached)")
	}

	// The process is still alive to reach this line at all -- that
	// alone is most of what this test proves. Now prove a second,
	// unrelated connection still works normally afterward.
	connB, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer func() { _ = connB.Close() }()

	nlri := bgp.NewIPAddrPrefix(24, "203.0.114.0")
	pathAttrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65099}),
		}),
		bgp.NewPathAttributeNextHop("192.0.2.99"),
	}
	update := bgp.NewBGPUpdateMessage(nil, pathAttrs, []*bgp.IPAddrPrefix{nlri})
	peerHeader := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, 0, 0, "198.51.100.2", 65099, "198.51.100.2", 1758700001.0)
	healthyWire, err := bmp.NewBMPRouteMonitoring(*peerHeader, update).Serialize()
	if err != nil {
		t.Fatalf("serialize healthy message: %v", err)
	}
	if _, err := connB.Write(healthyWire); err != nil {
		t.Fatalf("write B: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && healthyRecords.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if healthyRecords.Load() == 0 {
		t.Fatalf("connection B's record was never delivered -- connection A's panic took the collector down")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestCollector_ForwardsPartialRecordOnInnerAttributeParseError is the
// regression test for fix #5: gobgp's ParseBMPMessage can return a
// non-nil *BMPMessage (with Header and PeerHeader already fully decoded)
// alongside a non-nil error, specifically for a BMP_MSG_ROUTE_MONITORING
// message whose inner BGP UPDATE has a field it can't parse. Verified
// directly against gobgp (not just this package's own encoder): starting
// from a message built via buildSyntheticRouteMonitoring, corrupting the
// inner BGP UPDATE's WithdrawnRoutesLen field (bytes 67-68 of the wire:
// 6-byte BMP header + 42-byte peer header + 19-byte BGP header, right at
// the start of the UPDATE body) to a value exceeding the actual message
// length makes bgp.ParseBGPMessage fail with "withdrawn route length
// exceeds message length" while bmp.ParseBMPMessage still returns the
// message with Header/PeerHeader intact.
//
// The old code's blanket "if err != nil { continue }" dropped this
// entire record, discarding the successfully-decoded peer identity along
// with the genuinely-failed body. The fix must forward it instead.
func TestCollector_ForwardsPartialRecordOnInnerAttributeParseError(t *testing.T) {
	wire := buildSyntheticRouteMonitoring(t)

	// Sanity-check our understanding of the wire layout before
	// relying on it, so a future gobgp upgrade that changes framing
	// fails this assertion loudly instead of silently corrupting the
	// wrong bytes.
	const (
		bmpHdrLen  = 6
		peerHdrLen = 42
		bgpHdrLen  = 19
	)
	withdrawnLenOffset := bmpHdrLen + peerHdrLen + bgpHdrLen
	if len(wire) < withdrawnLenOffset+2 {
		t.Fatalf("synthetic wire too short (%d bytes) to corrupt at offset %d", len(wire), withdrawnLenOffset)
	}

	corrupted := append([]byte(nil), wire...)
	corrupted[withdrawnLenOffset] = 0xff
	corrupted[withdrawnLenOffset+1] = 0xff

	// Confirm this actually reproduces gobgp's (msg != nil, err !=
	// nil) case directly, independent of this package's Collector,
	// so a future gobgp change that stops exhibiting this behavior
	// fails this precondition check with a clear message rather than
	// this test silently passing for the wrong reason.
	msg, err := bmp.ParseBMPMessage(corrupted)
	if err == nil {
		t.Fatalf("precondition failed: corrupting WithdrawnRoutesLen did not produce a decode error from gobgp")
	}
	if msg == nil {
		t.Fatalf("precondition failed: gobgp returned a nil message alongside the error -- expected the documented (msg, err) partial-success case for BMP_MSG_ROUTE_MONITORING")
	}

	var (
		mu      sync.Mutex
		records []Record
		errs    []error
	)
	c := New("127.0.0.1:0", func(r Record) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, r)
	}, WithErrorCallback(func(_ net.Addr, _ bool, err error) {
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, err)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(corrupted); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(records)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Copy out what we need and release mu BEFORE calling Shutdown:
	// Shutdown closes this connection, which makes serveConn's own
	// error path try to call the ErrorCallback above (which also
	// locks mu) as part of Shutdown's synchronous teardown. Holding
	// mu across the Shutdown call would deadlock the two against
	// each other (bounded only by shutdownCtx's own timeout).
	mu.Lock()
	numRecords := len(records)
	numErrs := len(errs)
	var rec Record
	if numRecords > 0 {
		rec = records[0]
	}
	mu.Unlock()

	if numRecords != 1 {
		t.Fatalf("got %d records, want 1 (the partially-decoded one forwarded despite the body decode error)", numRecords)
	}
	if numErrs == 0 {
		t.Fatalf("expected the decode error to also be reported via ErrorCallback")
	}
	if rec.Message == nil {
		t.Fatalf("record's Message is nil, want the partially-decoded *bmp.BMPMessage")
	}
	if got := rec.PeerHeader.PeerAddress.String(); got != "198.51.100.1" {
		t.Fatalf("PeerHeader.PeerAddress = %s, want 198.51.100.1 (preserved despite the body decode error)", got)
	}
	if rec.PeerHeader.PeerAS != 65010 {
		t.Fatalf("PeerHeader.PeerAS = %d, want 65010 (preserved despite the body decode error)", rec.PeerHeader.PeerAS)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestWithErrorCallback covers the WithErrorCallback option end to end
// (previously 0% covered): it must actually be invoked, with the
// connection's remote address and a wrapped error, when a connection
// hits a read/decode error.
func TestWithErrorCallback(t *testing.T) {
	var (
		mu                sync.Mutex
		got               []error
		addr              net.Addr
		gotHandshakeState bool
	)
	c := New("127.0.0.1:0", func(Record) {}, WithErrorCallback(func(a net.Addr, handshakeComplete bool, err error) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, err)
		addr = a
		gotHandshakeState = handshakeComplete
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dialAddr := c.listener.Addr().String()

	conn, err := net.Dial("tcp", dialAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// An invalid-version header: guaranteed to produce a decode
	// error via splitBMPMessage.
	if _, err := conn.Write([]byte{0x63, 0x00, 0x00, 0x00, 0x06, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatalf("WithErrorCallback's callback was never invoked")
	}
	if addr == nil {
		t.Fatalf("WithErrorCallback's callback got a nil addr")
	}
	if !errors.Is(got[0], errInvalidBMPHeader) {
		t.Fatalf("error = %v, want it to wrap errInvalidBMPHeader", got[0])
	}
	if gotHandshakeState {
		t.Fatalf("handshakeComplete = true, want false (this connection never sent a valid Initiation)")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestWithLogger covers the WithLogger option end to end (previously 0%
// covered): the Collector must actually use the supplied *slog.Logger
// (not slog.Default()) for its own lifecycle/connection logging.
func TestWithLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	c := New("127.0.0.1:0", func(Record) {}, WithLogger(logger))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	// Give the "router connected"/"router disconnected" log lines a
	// moment to land.
	time.Sleep(200 * time.Millisecond)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "bmpcollector: listening") {
		t.Fatalf("supplied logger did not receive the \"listening\" log line; got:\n%s", out)
	}
	if !strings.Contains(out, "bmpcollector: router connected") {
		t.Fatalf("supplied logger did not receive the \"router connected\" log line; got:\n%s", out)
	}
}
