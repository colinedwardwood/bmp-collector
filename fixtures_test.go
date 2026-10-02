package bmpcollector

// fixtures_test.go builds one synthetic, wire-serialized BMP message per
// RFC 7854 §4.2 message type, using gobgp's own constructors/encoder (the
// same approach as buildSyntheticRouteMonitoring in collector_test.go: a
// self-serialize/self-parse round trip that proves this package's framing
// and decode wiring, not interop with real router firmware -- see
// README.md "Open questions").
//
// These are shared by:
//   - fixtures_test.go's own per-type decode tests (TestDecode_*), which
//     assert each message type actually makes it through
//     splitBMPMessage + bmp.ParseBMPMessage with its type-specific body
//     fields intact.
//   - fuzz_test.go's seed corpus, so the fuzzer starts from a population
//     of known-valid messages across every message type instead of only
//     RouteMonitoring.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// testPeerHeader returns a BMPPeerHeader shared by every fixture below
// (except Initiation/Termination, which carry no peer header per RFC 7854
// §4.1). A single shared helper keeps the fixtures focused on what varies
// per message type.
func testPeerHeader() *bmp.BMPPeerHeader {
	return bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_GLOBAL,
		0, // flags: pre-policy, IPv4
		0, // route distinguisher
		"198.51.100.1",
		65010,
		"198.51.100.1",
		1758700000.0,
	)
}

// buildRouteMonitoring is collector_test.go's buildSyntheticRouteMonitoring,
// kept there (it predates this file and existing tests reference it by
// that name) -- included here only as documentation of which of the 7
// RFC 7854 types is covered where:
//
//  1. RouteMonitoring   -- collector_test.go: buildSyntheticRouteMonitoring
//  2. StatisticsReport  -- below: buildStatisticsReport
//  3. PeerUpNotification   -- below: buildPeerUpNotification
//  4. PeerDownNotification -- below: buildPeerDownNotification
//  5. Initiation        -- below: buildInitiation
//  6. Termination       -- below: buildTermination
//  7. RouteMirroring    -- below: buildRouteMirroring

// buildStatisticsReport constructs a BMP StatisticsReport message (RFC
// 7854 §4.8) carrying a mix of 32-bit, 64-bit, and per-AFI/SAFI 64-bit
// stat TLVs, and returns its serialized wire bytes.
func buildStatisticsReport(t testing.TB) []byte {
	t.Helper()

	stats := []bmp.BMPStatsTLVInterface{
		bmp.NewBMPStatsTLV32(bmp.BMP_STAT_TYPE_REJECTED, 7),
		bmp.NewBMPStatsTLV64(bmp.BMP_STAT_TYPE_ADJ_RIB_IN, 1234567),
		bmp.NewBMPStatsTLVPerAfiSafi64(bmp.BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_IN, bgp.AFI_IP, uint8(bgp.SAFI_UNICAST), 42),
	}
	msg := bmp.NewBMPStatisticsReport(*testPeerHeader(), stats)

	wire, err := msg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic BMP StatisticsReport: %v", err)
	}
	return wire
}

// buildPeerUpNotification constructs a BMP PeerUpNotification message (RFC
// 7854 §4.10), carrying a sent and received BGP OPEN message, and returns
// its serialized wire bytes.
func buildPeerUpNotification(t testing.TB) []byte {
	t.Helper()

	sentOpen := bgp.NewBGPOpenMessage(65010, 180, "198.51.100.1", []bgp.OptionParameterInterface{
		bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{
			bgp.NewCapRouteRefresh(),
		}),
	})
	recvOpen := bgp.NewBGPOpenMessage(65020, 180, "198.51.100.2", []bgp.OptionParameterInterface{
		bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{
			bgp.NewCapRouteRefresh(),
		}),
	})

	msg := bmp.NewBMPPeerUpNotification(*testPeerHeader(), "198.51.100.1", 179, 52953, sentOpen, recvOpen)

	wire, err := msg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic BMP PeerUpNotification: %v", err)
	}
	return wire
}

// buildPeerDownNotification constructs a BMP PeerDownNotification message
// (RFC 7854 §4.9) using the "remote system closed with a BGP
// NOTIFICATION" reason, and returns its serialized wire bytes.
func buildPeerDownNotification(t testing.TB) []byte {
	t.Helper()

	notif := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
	msg := bmp.NewBMPPeerDownNotification(*testPeerHeader(), bmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION, notif, nil)

	wire, err := msg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic BMP PeerDownNotification: %v", err)
	}
	return wire
}

// buildInitiation constructs a BMP Initiation message (RFC 7854 §4.3),
// which carries no peer header, and returns its serialized wire bytes.
func buildInitiation(t testing.TB) []byte {
	t.Helper()

	info := []bmp.BMPInfoTLVInterface{
		bmp.NewBMPInfoTLVString(bmp.BMP_INIT_TLV_TYPE_STRING, "test collector initiation"),
		bmp.NewBMPInfoTLVString(bmp.BMP_INIT_TLV_TYPE_SYS_NAME, "router1.example.net"),
	}
	msg := bmp.NewBMPInitiation(info)

	wire, err := msg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic BMP Initiation: %v", err)
	}
	return wire
}

// buildTermination constructs a BMP Termination message (RFC 7854 §4.4),
// which also carries no peer header, and returns its serialized wire
// bytes.
func buildTermination(t testing.TB) []byte {
	t.Helper()

	info := []bmp.BMPTermTLVInterface{
		bmp.NewBMPTermTLVString(bmp.BMP_TERM_TLV_TYPE_STRING, "administratively shut down"),
		bmp.NewBMPTermTLV16(bmp.BMP_TERM_TLV_TYPE_REASON, 0 /* BMP_TERM_REASON_ADMIN */),
	}
	msg := bmp.NewBMPTermination(info)

	wire, err := msg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic BMP Termination: %v", err)
	}
	return wire
}

// buildRouteMirroring constructs a BMP RouteMirroring message (RFC 7854
// §4.7) carrying a mirrored BGP UPDATE TLV, and returns its serialized
// wire bytes.
func buildRouteMirroring(t testing.TB) []byte {
	t.Helper()

	nlri := bgp.NewIPAddrPrefix(24, "203.0.113.0")
	pathAttrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65002}),
		}),
		bgp.NewPathAttributeNextHop("192.0.2.1"),
	}
	update := bgp.NewBGPUpdateMessage(nil, pathAttrs, []*bgp.IPAddrPrefix{nlri})

	info := []bmp.BMPRouteMirrTLVInterface{
		bmp.NewBMPRouteMirrTLVBGPMsg(bmp.BMP_ROUTE_MIRRORING_TLV_TYPE_BGP_MSG, update),
	}
	msg := bmp.NewBMPRouteMirroring(*testPeerHeader(), info)

	wire, err := msg.Serialize()
	if err != nil {
		t.Fatalf("serialize synthetic BMP RouteMirroring: %v", err)
	}
	return wire
}

// allFixtures returns one wire-serialized message per RFC 7854 message
// type, labeled, for tests that want to exercise all 7 uniformly (e.g.
// the fuzz seed corpus).
func allFixtures(t testing.TB) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"route_monitoring":       buildSyntheticRouteMonitoring(t),
		"statistics_report":      buildStatisticsReport(t),
		"peer_up_notification":   buildPeerUpNotification(t),
		"peer_down_notification": buildPeerDownNotification(t),
		"initiation":             buildInitiation(t),
		"termination":            buildTermination(t),
		"route_mirroring":        buildRouteMirroring(t),
	}
}

// decodeOverTCP is the shared harness for TestDecode_*: start a real
// Collector on loopback, dial in, write one message, and return the
// single decoded Record (or fail the test).
func decodeOverTCP(t testing.TB, wire []byte) Record {
	t.Helper()

	recordCh := make(chan Record, 1)
	c := New("127.0.0.1:0", func(r Record) {
		recordCh <- r
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := c.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial collector: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var rec Record
	select {
	case rec = <-recordCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for decoded record")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := c.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	return rec
}

func TestDecode_StatisticsReport(t *testing.T) {
	rec := decodeOverTCP(t, buildStatisticsReport(t))

	if rec.Message == nil {
		t.Fatalf("Message is nil")
	}
	if rec.Message.Header.Type != bmp.BMP_MSG_STATISTICS_REPORT {
		t.Fatalf("Header.Type = %d, want BMP_MSG_STATISTICS_REPORT", rec.Message.Header.Type)
	}
	body, ok := rec.Message.Body.(*bmp.BMPStatisticsReport)
	if !ok {
		t.Fatalf("Body is %T, want *bmp.BMPStatisticsReport", rec.Message.Body)
	}
	if len(body.Stats) != 3 {
		t.Fatalf("got %d stat TLVs, want 3", len(body.Stats))
	}
	if rec.PeerHeader.PeerAS != 65010 {
		t.Fatalf("PeerHeader.PeerAS = %d, want 65010", rec.PeerHeader.PeerAS)
	}
}

// TestDecode_StatisticsReportPartialBodyForwardsPeerIdentity is the
// regression test for fix #3: before this fix, a StatisticsReport (or
// PeerUpNotification/PeerDownNotification/RouteMirroring) message whose
// body failed to parse was dropped in its entirety, peer identity
// included -- because gobgp's own ParseBMPMessage discards msg (returns
// nil) for every message type except BMP_MSG_ROUTE_MONITORING when Body
// fails to decode, even though Header and PeerHeader had, in every case,
// already decoded successfully. parseBMPMessagePreservingPartial fixes
// this by reimplementing the decode sequence itself and always
// forwarding msg regardless of type.
//
// Corrupts the first stat TLV's declared Length field (bytes 54-55 of
// the wire: 6-byte BMP header + 42-byte peer header + 4-byte Count,
// right at the start of the first TLV's own Length field) to a value
// exceeding the remaining buffer, which makes
// BMPStatisticsReport.ParseBody fail with "value length is not enough"
// before decoding any TLV -- a clean, deterministic body-decode failure
// with Header/PeerHeader already fully decoded, parallel to
// TestCollector_ForwardsPartialRecordOnInnerAttributeParseError's
// RouteMonitoring case in collector_test.go.
func TestDecode_StatisticsReportPartialBodyForwardsPeerIdentity(t *testing.T) {
	wire := buildStatisticsReport(t)

	const (
		bmpHdrLen  = 6
		peerHdrLen = 42
		countLen   = 4
		tlvTypeLen = 2
	)
	lengthFieldOffset := bmpHdrLen + peerHdrLen + countLen + tlvTypeLen
	if len(wire) < lengthFieldOffset+2 {
		t.Fatalf("synthetic wire too short (%d bytes) to corrupt at offset %d", len(wire), lengthFieldOffset)
	}

	corrupted := append([]byte(nil), wire...)
	corrupted[lengthFieldOffset] = 0xff
	corrupted[lengthFieldOffset+1] = 0xff

	// Confirm this actually reproduces gobgp's documented (nil, err)
	// full-record-loss case directly, independent of this package's
	// Collector, so a future gobgp change that stops exhibiting this
	// behavior fails this precondition check with a clear message
	// instead of this test silently passing for the wrong reason.
	if _, err := bmp.ParseBMPMessage(corrupted); err == nil {
		t.Fatalf("precondition failed: corrupting the TLV Length field did not produce a decode error from gobgp")
	}
	if msg, _ := bmp.ParseBMPMessage(corrupted); msg != nil {
		t.Fatalf("precondition failed: gobgp.ParseBMPMessage returned a non-nil message for StatisticsReport -- expected the documented nil-on-error case this fix generalizes past")
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

	mu.Lock()
	numRecords := len(records)
	numErrs := len(errs)
	var rec Record
	if numRecords > 0 {
		rec = records[0]
	}
	mu.Unlock()

	if numRecords != 1 {
		t.Fatalf("got %d records, want 1 (the partially-decoded StatisticsReport forwarded despite the body decode error)", numRecords)
	}
	if numErrs == 0 {
		t.Fatalf("expected the decode error to also be reported via ErrorCallback")
	}
	if rec.Message == nil {
		t.Fatalf("record's Message is nil, want the partially-decoded *bmp.BMPMessage")
	}
	if rec.Message.Header.Type != bmp.BMP_MSG_STATISTICS_REPORT {
		t.Fatalf("Header.Type = %d, want BMP_MSG_STATISTICS_REPORT", rec.Message.Header.Type)
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

func TestDecode_PeerUpNotification(t *testing.T) {
	rec := decodeOverTCP(t, buildPeerUpNotification(t))

	if rec.Message == nil {
		t.Fatalf("Message is nil")
	}
	if rec.Message.Header.Type != bmp.BMP_MSG_PEER_UP_NOTIFICATION {
		t.Fatalf("Header.Type = %d, want BMP_MSG_PEER_UP_NOTIFICATION", rec.Message.Header.Type)
	}
	body, ok := rec.Message.Body.(*bmp.BMPPeerUpNotification)
	if !ok {
		t.Fatalf("Body is %T, want *bmp.BMPPeerUpNotification", rec.Message.Body)
	}
	if body.RemotePort != 52953 {
		t.Fatalf("RemotePort = %d, want 52953", body.RemotePort)
	}
	if body.SentOpenMsg == nil || body.ReceivedOpenMsg == nil {
		t.Fatalf("SentOpenMsg/ReceivedOpenMsg not decoded: sent=%v recv=%v", body.SentOpenMsg, body.ReceivedOpenMsg)
	}
	sentOpen, ok := body.SentOpenMsg.Body.(*bgp.BGPOpen)
	if !ok {
		t.Fatalf("SentOpenMsg.Body is %T, want *bgp.BGPOpen", body.SentOpenMsg.Body)
	}
	if sentOpen.MyAS != 65010 {
		t.Fatalf("SentOpenMsg MyAS = %d, want 65010", sentOpen.MyAS)
	}
}

func TestDecode_PeerDownNotification(t *testing.T) {
	rec := decodeOverTCP(t, buildPeerDownNotification(t))

	if rec.Message == nil {
		t.Fatalf("Message is nil")
	}
	if rec.Message.Header.Type != bmp.BMP_MSG_PEER_DOWN_NOTIFICATION {
		t.Fatalf("Header.Type = %d, want BMP_MSG_PEER_DOWN_NOTIFICATION", rec.Message.Header.Type)
	}
	body, ok := rec.Message.Body.(*bmp.BMPPeerDownNotification)
	if !ok {
		t.Fatalf("Body is %T, want *bmp.BMPPeerDownNotification", rec.Message.Body)
	}
	if body.Reason != bmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION {
		t.Fatalf("Reason = %d, want BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION", body.Reason)
	}
	if body.BGPNotification == nil {
		t.Fatalf("BGPNotification not decoded")
	}
	notif, ok := body.BGPNotification.Body.(*bgp.BGPNotification)
	if !ok {
		t.Fatalf("BGPNotification.Body is %T, want *bgp.BGPNotification", body.BGPNotification.Body)
	}
	if notif.ErrorCode != bgp.BGP_ERROR_CEASE {
		t.Fatalf("ErrorCode = %d, want BGP_ERROR_CEASE", notif.ErrorCode)
	}
}

func TestDecode_Initiation(t *testing.T) {
	rec := decodeOverTCP(t, buildInitiation(t))

	if rec.Message == nil {
		t.Fatalf("Message is nil")
	}
	if rec.Message.Header.Type != bmp.BMP_MSG_INITIATION {
		t.Fatalf("Header.Type = %d, want BMP_MSG_INITIATION", rec.Message.Header.Type)
	}
	if !rec.HandshakeComplete {
		t.Fatalf("HandshakeComplete = false, want true after an Initiation message")
	}
	body, ok := rec.Message.Body.(*bmp.BMPInitiation)
	if !ok {
		t.Fatalf("Body is %T, want *bmp.BMPInitiation", rec.Message.Body)
	}
	if len(body.Info) != 2 {
		t.Fatalf("got %d info TLVs, want 2", len(body.Info))
	}
}

func TestDecode_Termination(t *testing.T) {
	rec := decodeOverTCP(t, buildTermination(t))

	if rec.Message == nil {
		t.Fatalf("Message is nil")
	}
	if rec.Message.Header.Type != bmp.BMP_MSG_TERMINATION {
		t.Fatalf("Header.Type = %d, want BMP_MSG_TERMINATION", rec.Message.Header.Type)
	}
	body, ok := rec.Message.Body.(*bmp.BMPTermination)
	if !ok {
		t.Fatalf("Body is %T, want *bmp.BMPTermination", rec.Message.Body)
	}
	if len(body.Info) != 2 {
		t.Fatalf("got %d info TLVs, want 2", len(body.Info))
	}
}

func TestDecode_RouteMirroring(t *testing.T) {
	rec := decodeOverTCP(t, buildRouteMirroring(t))

	if rec.Message == nil {
		t.Fatalf("Message is nil")
	}
	if rec.Message.Header.Type != bmp.BMP_MSG_ROUTE_MIRRORING {
		t.Fatalf("Header.Type = %d, want BMP_MSG_ROUTE_MIRRORING", rec.Message.Header.Type)
	}
	body, ok := rec.Message.Body.(*bmp.BMPRouteMirroring)
	if !ok {
		t.Fatalf("Body is %T, want *bmp.BMPRouteMirroring", rec.Message.Body)
	}
	if len(body.Info) != 1 {
		t.Fatalf("got %d route-mirroring TLVs, want 1", len(body.Info))
	}
	if rec.PeerHeader.PeerAS != 65010 {
		t.Fatalf("PeerHeader.PeerAS = %d, want 65010", rec.PeerHeader.PeerAS)
	}
}
