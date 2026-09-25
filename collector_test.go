package bmpcollector

import (
	"context"
	"net"
	"sync"
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
func buildSyntheticRouteMonitoring(t *testing.T) []byte {
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
	defer conn.Close()

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
