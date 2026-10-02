package bmpcollector

// collector_fixes_test.go holds the regression tests for the second
// round of adversarial-review fixes (2026-10-02 finishing round):
//
//   - TestCollector_StartShutdownCycles_DoNotLeakGoroutines: fix #5,
//     the Start ctx-watcher goroutine-leak fix.
//   - TestReadOneBMPMessage_WaitsForBudget: fix #1, the aggregate-
//     memory/OOM admission control's core acquire/block/release
//     mechanism, tested directly against readOneBMPMessage and a
//     semaphore.Weighted over an in-memory net.Pipe (deterministic, not
//     timing-dependent on real goroutine scheduling across a TCP stack).
//   - TestCollector_AggregateBufferBudget_ShutdownUnblocksWaitingConnection:
//     the same fix's end-to-end interaction with Shutdown, over a real
//     Collector and real connections (a connection parked waiting on an
//     exhausted budget must not block Shutdown).
//   - TestCollector_AggregateBufferBudget_SteadyStateMemoryBounded: the
//     regression test for the subtler half of fix #1 -- many long-lived
//     connections that each received one large message must not
//     permanently retain that much memory each merely because the
//     connections stay open (RFC 7854 BMP sessions are long-lived by
//     design). An earlier version of this fix bounded only the *rate* of
//     new buffering (via a bufio.Scanner whose internal buffer, once
//     grown, never shrinks for the life of the connection) and still let
//     steady-state memory approach connections*maxMessageSize.
//
// The aggregate-memory bug itself (many ordinary connections, each
// individually within every existing per-connection/per-message cap,
// collectively exhausting process memory) is additionally reproduced
// directly against a real container memory limit as a separate,
// standalone repro (build a container, drive ~100-150 concurrent
// connections each sending one ~900KB message against it) -- that is
// infrastructure-level (Docker, cgroups) verification outside what a Go
// unit test can exercise, not duplicated here.
//
// issue #27 follow-up round (2026-10-02) added two more:
//
//   - TestParseBMPMessagePreservingPartial_TruncatedStatisticsReportBodyPanicsButPreservesPeerHeader
//   - TestParseBMPMessagePreservingPartial_TruncatedPeerUpNotificationBodyPanicsButPreservesPeerHeader
//
// Both are regression tests for the gap independent re-verification
// found in parseBMPMessagePreservingPartial's panic recovery: an earlier
// version's recover() wrapped the *entire* function and unconditionally
// discarded the already-decoded Header/PeerHeader (set msg = nil) on any
// panic, including a panic from gobgp's own unchecked slice indexing
// inside its BMPBody.ParseBody implementations (confirmed sites:
// BMPStatisticsReport.ParseBody's data[0:4],
// BMPPeerUpNotification.ParseBody's data[:16]) -- as opposed to
// TestDecode_StatisticsReportPartialBodyForwardsPeerIdentity in
// fixtures_test.go, which only ever exercises a graceful *error return*
// from ParseBody (a crafted TLV length), never this panic path. These
// two tests drive a message with a fully-present, otherwise-valid
// 6-byte header and 42-byte peer header, but a type-specific body
// deliberately truncated short enough to make gobgp's own ParseBody
// panic, and assert the panic is still recovered with Header/PeerHeader
// intact in the returned message -- exactly the white-box case the
// earlier regression test never reached.

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
	"golang.org/x/sync/semaphore"
)

// TestCollector_StartShutdownCycles_DoNotLeakGoroutines is the
// regression test for fix #5: Start's ctx-watcher goroutine (the one
// that proactively closes the listener on <-ctx.Done()) used not to be
// tracked in the Collector's wait group. For any caller that -- like
// every other test in this package, and like a typical production
// caller using a long-lived, never-cancelled parent context -- invokes
// Start with a context it does not go on to cancel before calling
// Shutdown, that goroutine parked forever, and Shutdown reported success
// without ever waiting for it. The adversarial review reproduced this
// directly: driving 20 Start/Shutdown cycles against the unpatched code
// with context.Background() (deliberately never cancelled) grew Go's
// live goroutine count monotonically, by one per cycle, with no
// corresponding decrease on Shutdown (observed: counts going 2->22 and
// 1->21 over 20 cycles in two separate runs).
//
// With the fix (shutdownCh lets Shutdown wake that goroutine without
// requiring ctx to be cancelled, and it's now tracked in c.wg), the
// goroutine count must return to its baseline after every single
// Shutdown, across many repeated cycles -- not just "eventually", which
// a flaky/slow leak could still satisfy by accident.
func TestCollector_StartShutdownCycles_DoNotLeakGoroutines(t *testing.T) {
	const cycles = 20

	// Let any goroutines left over from earlier subtests/test-binary
	// startup settle before taking the baseline.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := 0; i < cycles; i++ {
		// Deliberately context.Background(), never cancelled by this
		// test -- exactly the condition that leaked before the fix.
		ctx := context.Background()

		c := New("127.0.0.1:0", func(Record) {})
		if err := c.Start(ctx); err != nil {
			t.Fatalf("cycle %d: Start: %v", i, err)
		}

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := c.Shutdown(shutdownCtx)
		shutdownCancel()
		if err != nil {
			t.Fatalf("cycle %d: Shutdown: %v", i, err)
		}

		// Give the now-unblocked goroutines a brief moment to actually
		// finish unwinding past their defers before we count.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			runtime.GC()
			if n := runtime.NumGoroutine(); n <= baseline {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		if n := runtime.NumGoroutine(); n > baseline {
			t.Fatalf("cycle %d: goroutine count = %d, want <= baseline %d (leak)", i, n, baseline)
		}
	}
}

// bmpHeaderBytes builds just a 6-byte BMP header declaring length and
// type -- enough to drive readOneBMPMessage/splitBMPMessage's framing
// decision without needing a body that actually parses. Shared by the
// buffer-budget tests below, which only care about framing/admission,
// never about a message's body successfully decoding.
func bmpHeaderBytes(length uint32, msgType uint8) []byte {
	hdr := make([]byte, bmpHeaderSize)
	hdr[0] = bmp.BMP_VERSION
	binary.BigEndian.PutUint32(hdr[1:5], length)
	hdr[5] = msgType
	return hdr
}

// TestReadOneBMPMessage_WaitsForBudget is a direct, deterministic test
// of the aggregate-buffer-budget mechanism itself (fix #1, CRITICAL --
// see defaultMaxBufferedBytes/readOneBMPMessage): with the entire budget
// already held elsewhere, readOneBMPMessage must block in the semaphore
// -- not return early, not ignore the budget -- until that reservation
// is released, even though the full message is already fully available
// to read. This is the exact mechanism that, end to end over many real
// connections, bounds the aggregate memory the full Collector will
// buffer regardless of how many connections are open.
func TestReadOneBMPMessage_WaitsForBudget(t *testing.T) {
	const size = 100

	sem := semaphore.NewWeighted(size)
	// Simulate "another connection is already holding the entire
	// budget" by acquiring it ourselves first.
	if err := sem.Acquire(context.Background(), size); err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}

	serverSide, clientSide := net.Pipe()
	defer func() { _ = serverSide.Close() }()
	defer func() { _ = clientSide.Close() }()

	wire := bmpHeaderBytes(size, bmp.BMP_MSG_INITIATION)
	body := make([]byte, size-bmpHeaderSize)
	go func() {
		_, _ = clientSide.Write(wire)
		_, _ = clientSide.Write(body)
	}()

	r := bufio.NewReaderSize(serverSide, 4096)
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, _, err := readOneBMPMessage(context.Background(), r, sem)
		done <- result{raw, err}
	}()

	select {
	case <-done:
		t.Fatalf("readOneBMPMessage returned before the pre-existing reservation was released -- the budget did not block it")
	case <-time.After(200 * time.Millisecond):
		// Expected: still blocked in sem.Acquire, even though the full
		// message (header + body) is already sitting there to read.
	}

	sem.Release(size)

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("readOneBMPMessage: %v", res.err)
		}
		if len(res.raw) != size {
			t.Fatalf("len(raw) = %d, want %d", len(res.raw), size)
		}
		// Mirror what serveConn does after it's done with the message:
		// release readOneBMPMessage's own successful acquisition.
		sem.Release(size)
	case <-time.After(2 * time.Second):
		t.Fatalf("readOneBMPMessage is still blocked 2s after the budget was released")
	}
}

// TestCollector_AggregateBufferBudget_ShutdownUnblocksWaitingConnection
// covers fix #1's Shutdown interaction end to end, over a real
// Collector and real TCP connections: a connection that is currently
// blocked waiting for aggregate buffer budget (because the budget is
// fully consumed by another connection that never finishes) must not
// prevent Shutdown from returning promptly. Without per-connection ctx
// cancellation (see acceptLoop/serveConn), only a blocked Read is
// unblocked by Shutdown's conn.Close() calls -- a goroutine blocked in
// semaphore.Weighted.Acquire is not, and would hang until the
// Collector's own long-lived Start ctx is cancelled, which Shutdown
// deliberately does not do.
func TestCollector_AggregateBufferBudget_ShutdownUnblocksWaitingConnection(t *testing.T) {
	// maxBMPMessageSize exactly: New clamps any smaller
	// WithMaxBufferedBytes value up to this floor (so a single
	// max-size message can never be permanently unadmittable), so
	// using this size directly keeps the test's budget math exact
	// instead of fighting that clamp.
	const msgSize = uint32(maxBMPMessageSize)

	c := New("127.0.0.1:0", func(Record) {}, WithMaxBufferedBytes(int64(msgSize)), WithMaxConnections(4))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	// Connection A: send the full header declaring msgSize (so
	// readOneBMPMessage's Acquire for the whole budget succeeds
	// immediately, since nothing else holds it yet), then never send
	// the body. With the budget sized to exactly one max-size message,
	// A now permanently (for the test's duration) holds the entire
	// thing, blocked instead in the body Read -- itself still correctly
	// unblocked by this connection's own Close(), independent of this
	// test's actual target: connection B.
	connA, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer func() { _ = connA.Close() }()
	header := bmpHeaderBytes(msgSize, bmp.BMP_MSG_INITIATION)
	if _, err := connA.Write(header); err != nil {
		t.Fatalf("write A header: %v", err)
	}

	// Give A's goroutine a moment to actually acquire the reservation
	// before connection B tries (and blocks).
	time.Sleep(200 * time.Millisecond)

	// Connection B: the same declared size. With the budget fully
	// consumed by A, B's serveConn goroutine blocks inside
	// readOneBMPMessage's sem.Acquire -- not in a network Read -- for
	// as long as A holds its reservation. B also only needs to send
	// its header for this: the test never waits for B's message to be
	// delivered, only for Shutdown to return.
	connB, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer func() { _ = connB.Close() }()
	if _, err := connB.Write(header); err != nil {
		t.Fatalf("write B header: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // let B's goroutine actually reach the blocked Acquire

	start := time.Now()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown did not return cleanly: %v (elapsed %v)", err, time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Shutdown took %v, want well under its 3s deadline (connection B's budget wait should be cancelled, not merely timed out)", elapsed)
	}
}

// TestCollector_AggregateBufferBudget_SteadyStateMemoryBounded is the
// regression test for the subtler half of fix #1: it isn't enough to
// bound the *rate* at which new buffering can start if the memory each
// admitted message used is still retained forever afterward. An earlier
// version of this fix read each message's body into a
// connection-lifetime bufio.Scanner's own internal buffer, which only
// ever grows, never shrinks -- so once a connection had received one
// large message, it permanently retained that much capacity for as long
// as the connection stayed open, which for BMP (RFC 7854's sessions are
// one long-lived TCP connection per monitored router, not one per
// message) meant steady-state memory still approached
// connections*maxMessageSize, reintroducing the exact unbounded-product
// condition this fix exists to close off -- just more gradually than
// the original instantaneous-OOM repro, rather than genuinely bounded.
//
// This drives many more connections than the budget could ever admit
// concurrently, each sending one maximum-size message and then staying
// open (idle) afterward -- exactly the shape that exposed the bug -- and
// asserts that once every message has been processed, live heap stays
// within a small multiple of the configured budget, not anywhere near
// connections*maxMessageSize.
func TestCollector_AggregateBufferBudget_SteadyStateMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates/holds open ~100 real connections; skipped in -short")
	}

	const (
		msgSize = uint32(maxBMPMessageSize) // 1 MiB: the largest single message possible.
		nConns  = 100
		budget  = int64(8 << 20) // 8 MiB -- nConns*msgSize would be ~100 MiB if unbounded.
	)

	// Only onError counts: this test's messages have a valid
	// RouteMonitoring header/peer-header but a body that always fails
	// to parse (see the comment on wire below), which -- per fix #3 --
	// forwards a partial Record to onRecord *in addition to* reporting
	// the error via onError. Counting both would double-count.
	var processed atomic.Int32
	c := New("127.0.0.1:0", func(Record) {},
		WithMaxBufferedBytes(budget), WithMaxConnections(nConns+1),
		WithErrorCallback(func(net.Addr, bool, error) { processed.Add(1) }))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	// A RouteMonitoring-typed message (not Initiation/StatisticsReport),
	// full-size (header + an all-zero body, unlike bmpHeaderBytes'
	// header-only output -- every connection must actually send the
	// whole declared message for this test to exercise real buffering):
	// an all-zero body decodes as a BGP header whose Len field is 0,
	// which gobgp's bgp.BGPHeader.DecodeFromBytes rejects immediately
	// (O(1), independent of the declared message size) -- unlike
	// Initiation/StatisticsReport, whose all-zero body instead decodes
	// as a very long run of valid zero-length TLVs, an O(n) allocation
	// cost of its own that would confound this test with a second,
	// unrelated memory effect.
	wire := make([]byte, msgSize)
	copy(wire, bmpHeaderBytes(msgSize, bmp.BMP_MSG_ROUTE_MONITORING))

	conns := make([]net.Conn, 0, nConns)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < nConns; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, conn)

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			_, _ = conn.Write(wire) // best-effort; failures surface as processed never reaching nConns below
		}(conn)
	}
	wg.Wait()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && processed.Load() < nConns {
		time.Sleep(20 * time.Millisecond)
	}
	if got := processed.Load(); got != nConns {
		t.Fatalf("processed %d of %d messages before timing out", got, nConns)
	}

	// All nConns messages are now fully handled, but every connection
	// is still open (idle) -- the exact condition that exposed the bug.
	runtime.GC()
	runtime.GC() // a second pass to let any finalizer-adjacent cycles settle.
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// Generous but meaningful: the bug this guards against would put
	// live heap near nConns*msgSize (~100 MiB); a correctly-bounded
	// implementation should stay within a small multiple of budget
	// (8 MiB) plus ordinary runtime/test-process overhead.
	const maxAcceptableHeap = 64 << 20 // 64 MiB
	if mem.HeapAlloc > maxAcceptableHeap {
		t.Fatalf("HeapAlloc = %d bytes (%.1f MiB) after all connections went idle, want <= %d bytes (%.1f MiB) -- memory from already-processed messages is being retained per idle connection instead of released",
			mem.HeapAlloc, float64(mem.HeapAlloc)/(1<<20), maxAcceptableHeap, float64(maxAcceptableHeap)/(1<<20))
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// truncateBMPBodyAfterPeerHeader takes a full wire-serialized BMP
// message (6-byte header + 42-byte peer header + type-specific body)
// and returns a corrupted copy whose type-specific body is truncated to
// exactly truncatedBodyLen bytes, with the BMP header's own Length field
// rewritten to match the new (shorter) total so this collector's own
// framing reads exactly that many bytes -- the rewritten Length is what
// makes this a realistic "short body" input (as opposed to simply
// slicing the wire bytes and leaving Length claiming the original,
// larger size, which readOneBMPMessage would instead treat as "wait for
// more bytes that will never arrive").
func truncateBMPBodyAfterPeerHeader(t testing.TB, wire []byte, truncatedBodyLen int) []byte {
	t.Helper()
	const (
		bmpHdrLen  = 6
		peerHdrLen = 42
	)
	newLen := bmpHdrLen + peerHdrLen + truncatedBodyLen
	if newLen > len(wire) {
		t.Fatalf("truncateBMPBodyAfterPeerHeader: truncated length %d exceeds original wire length %d", newLen, len(wire))
	}
	out := append([]byte(nil), wire[:newLen]...)
	binary.BigEndian.PutUint32(out[1:5], uint32(newLen))
	return out
}

// ipv6TestPeerHeader is testPeerHeader's (fixtures_test.go) IPv6
// counterpart: bmp.NewBMPPeerHeader sets BMP_PEER_FLAG_IPV6 in Flags
// automatically whenever the given address doesn't parse as IPv4, which
// TestParseBMPMessagePreservingPartial_TruncatedPeerUpNotificationBodyPanicsButPreservesPeerHeader
// needs to drive BMPPeerUpNotification.ParseBody down its
// `data[:16]` (IPv6) branch rather than its `data[12:16]` (IPv4) one --
// both unchecked on gobgp's side, but the IPv6 branch is the exact one
// issue #27 cited.
func ipv6TestPeerHeader() *bmp.BMPPeerHeader {
	return bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_GLOBAL,
		0, // flags: pre-policy; IPv6 is set automatically below
		0, // route distinguisher
		"2001:db8::1",
		65010,
		"198.51.100.1",
		1758700000.0,
	)
}

// TestParseBMPMessagePreservingPartial_TruncatedStatisticsReportBodyPanicsButPreservesPeerHeader
// is a regression test for the issue #27 follow-up gap: a
// StatisticsReport whose body (after a fully-present, 42-byte peer
// header) is shorter than the 4 bytes BMPStatisticsReport.ParseBody
// unconditionally reads for its Count field (data[0:4]), with no length
// check of its own, panics inside gobgp's code -- and the panic-recovery
// handler in place before this fix discarded the Header/PeerHeader that
// had, by that point, already decoded successfully. Unlike
// TestDecode_StatisticsReportPartialBodyForwardsPeerIdentity
// (fixtures_test.go), which corrupts a TLV length deep inside an
// otherwise-long-enough body (a graceful, non-panicking error from
// gobgp), this corrupts the body's own length so gobgp panics.
func TestParseBMPMessagePreservingPartial_TruncatedStatisticsReportBodyPanicsButPreservesPeerHeader(t *testing.T) {
	wire := buildStatisticsReport(t)
	// 2 bytes: shorter than the 4 bytes BMPStatisticsReport.ParseBody
	// needs for data[0:4].
	const truncatedBodyLen = 2
	corrupted := truncateBMPBodyAfterPeerHeader(t, wire, truncatedBodyLen)

	// Precondition: confirm this still panics inside gobgp's own
	// BMPStatisticsReport.ParseBody today, directly, independent of this
	// package's recovery wrapper -- so a future gobgp release that adds
	// its own bounds check fails this precondition with a clear message
	// instead of the rest of this test silently passing for the wrong
	// reason.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("precondition failed: gobgp's BMPStatisticsReport.ParseBody did not panic on a %d-byte body; this test no longer reproduces the gap it targets", truncatedBodyLen)
			}
		}()
		body := &bmp.BMPStatisticsReport{}
		truncatedBody := corrupted[6+42:]
		_ = body.ParseBody(&bmp.BMPMessage{}, truncatedBody)
	}()

	msg, err := parseBMPMessagePreservingPartial(corrupted)
	if err == nil {
		t.Fatalf("expected a non-nil error recovered from the body-decode panic")
	}
	if msg == nil {
		t.Fatalf("msg is nil: the panic-recovery path discarded the already-decoded Header/PeerHeader -- the exact gap this test targets")
	}
	if msg.Header.Type != bmp.BMP_MSG_STATISTICS_REPORT {
		t.Fatalf("Header.Type = %d, want BMP_MSG_STATISTICS_REPORT", msg.Header.Type)
	}
	if got := msg.PeerHeader.PeerAddress.String(); got != "198.51.100.1" {
		t.Fatalf("PeerHeader.PeerAddress = %s, want 198.51.100.1 (preserved despite the body-decode panic)", got)
	}
	if msg.PeerHeader.PeerAS != 65010 {
		t.Fatalf("PeerHeader.PeerAS = %d, want 65010 (preserved despite the body-decode panic)", msg.PeerHeader.PeerAS)
	}
}

// TestParseBMPMessagePreservingPartial_TruncatedPeerUpNotificationBodyPanicsButPreservesPeerHeader
// is the PeerUpNotification counterpart of the StatisticsReport test
// above: a body (after a fully-present, 42-byte peer header) shorter
// than the 16 bytes BMPPeerUpNotification.ParseBody unconditionally
// reads for its IPv6 LocalAddress field (data[:16]) when the peer
// header's IPv6 flag is set, with no length check of its own, panics
// inside gobgp's code. Same gap, same fix, different message type and
// different one of the two confirmed panic sites (issue #27: "data[:16]
// and data[0:4] patterns").
func TestParseBMPMessagePreservingPartial_TruncatedPeerUpNotificationBodyPanicsButPreservesPeerHeader(t *testing.T) {
	sentOpen := bgp.NewBGPOpenMessage(65010, 180, "198.51.100.1", nil)
	recvOpen := bgp.NewBGPOpenMessage(65020, 180, "198.51.100.2", nil)
	peer := ipv6TestPeerHeader()
	msg := bmp.NewBMPPeerUpNotification(*peer, "2001:db8::1", 179, 52953, sentOpen, recvOpen)
	wire, err := msg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic IPv6 BMP PeerUpNotification: %v", err)
	}

	// 5 bytes: shorter than the 16 bytes BMPPeerUpNotification.ParseBody
	// needs for data[:16] on the IPv6 path.
	const truncatedBodyLen = 5
	corrupted := truncateBMPBodyAfterPeerHeader(t, wire, truncatedBodyLen)

	// Precondition: confirm this still panics inside gobgp's own
	// BMPPeerUpNotification.ParseBody today, directly, independent of
	// this package's recovery wrapper (see the StatisticsReport test
	// above for why).
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("precondition failed: gobgp's BMPPeerUpNotification.ParseBody did not panic on a %d-byte IPv6 body; this test no longer reproduces the gap it targets", truncatedBodyLen)
			}
		}()
		body := &bmp.BMPPeerUpNotification{}
		truncatedBody := corrupted[6+42:]
		_ = body.ParseBody(&bmp.BMPMessage{PeerHeader: *peer}, truncatedBody)
	}()

	parsed, perr := parseBMPMessagePreservingPartial(corrupted)
	if perr == nil {
		t.Fatalf("expected a non-nil error recovered from the body-decode panic")
	}
	if parsed == nil {
		t.Fatalf("msg is nil: the panic-recovery path discarded the already-decoded Header/PeerHeader -- the exact gap this test targets")
	}
	if parsed.Header.Type != bmp.BMP_MSG_PEER_UP_NOTIFICATION {
		t.Fatalf("Header.Type = %d, want BMP_MSG_PEER_UP_NOTIFICATION", parsed.Header.Type)
	}
	if got := parsed.PeerHeader.PeerAddress.String(); got != "2001:db8::1" {
		t.Fatalf("PeerHeader.PeerAddress = %s, want 2001:db8::1 (preserved despite the body-decode panic)", got)
	}
	if parsed.PeerHeader.PeerAS != 65010 {
		t.Fatalf("PeerHeader.PeerAS = %d, want 65010 (preserved despite the body-decode panic)", parsed.PeerHeader.PeerAS)
	}
}
