package bmpcollector

import (
	"testing"
)

// fuzz_test.go fuzzes the same two-stage decode path serveConn drives on
// every byte that arrives on a connection: splitBMPMessage (this
// package's framing fix on top of gobgp's header decode) followed by
// parseBMPMessagePreservingPartial (this package's own panic-recovering
// wrapper around gobgp's message-body decode -- see that function's doc
// comment -- which is what serveConn actually calls today, in place of
// calling bmp.ParseBMPMessage directly) on whatever token splitBMPMessage
// produces. It does not go through a real net.Conn / bufio.Scanner --
// splitBMPMessage already implements the bufio.SplitFunc contract
// directly against a byte slice, so calling it in a loop over successive
// advances reproduces exactly what the Scanner does, without needing a
// goroutine+socket per fuzz input.
//
// Goal: catch a regression in the Length=0 / invalid-version framing fix
// (see splitBMPMessage's doc comment and the CRITICAL bug writeups in
// collector_test.go) automatically, plus any input that makes either
// function panic, hang, or return advance/token values that violate the
// bufio.SplitFunc contract (e.g. advance > len(data), or advance == 0
// with a non-nil token).
//
// Seeded with:
//   - one serialized fixture per RFC 7854 message type (allFixtures, see
//     fixtures_test.go) -- known-good input across every message type,
//     not just RouteMonitoring.
//   - the exact known-malicious byte patterns from the earlier
//     adversarial-review round: a Length=0 header (busy-loop bug) and an
//     invalid version byte (silent-block bug).
//   - a couple of additional boundary patterns (truncated header, Length
//     just over maxBMPMessageSize) that are the kind of input a fuzzer
//     would otherwise have to rediscover from scratch.
func FuzzSplitAndParseBMPMessage(f *testing.F) {
	// allFixtures takes testing.TB (satisfied by both *testing.T and
	// *testing.F) specifically so it can be reused here to seed the
	// fuzz corpus with one real, valid, wire-serialized message per RFC
	// 7854 type.
	for _, wire := range allFixtures(f) {
		f.Add(wire)
	}

	// CRITICAL bug #1a: Length (0) smaller than the 6-byte header itself.
	f.Add([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00})
	// CRITICAL bug #1b: invalid version byte.
	f.Add([]byte{0x63, 0x00, 0x00, 0x00, 0x06, 0x00})
	// Truncated header (fewer than bmpHeaderSize bytes total).
	f.Add([]byte{0x03, 0x00, 0x00})
	// Syntactically valid header, Length says more data follows than is
	// actually present (mid-message truncation).
	f.Add([]byte{0x03, 0x00, 0x00, 0x00, 0xff, 0x00})
	// Length exceeds maxBMPMessageSize.
	f.Add([]byte{0x03, 0xff, 0xff, 0xff, 0xff, 0x00})
	// Empty input.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Drive splitBMPMessage exactly as bufio.Scanner would: repeatedly
		// call it with atEOF=false (there is always "more data" available
		// in principle for a fuzz corpus entry, since it's not a real
		// stream), consuming `advance` bytes each time, until it asks for
		// more data (advance==0, token==nil, err==nil) or errors out. This
		// bounds the loop at len(data) iterations in the worst case (each
		// successful token must advance by at least 1 byte or the
		// function's own precondition -- enforced below -- would catch it).
		remaining := data
		iterations := 0
		for len(remaining) > 0 {
			iterations++
			if iterations > len(data)+1 {
				t.Fatalf("splitBMPMessage made no forward progress on remaining input of length %d (possible infinite loop)", len(remaining))
			}

			advance, token, err := splitBMPMessage(remaining, false)

			if advance < 0 || advance > len(remaining) {
				t.Fatalf("splitBMPMessage returned invalid advance=%d for input of length %d", advance, len(remaining))
			}
			if err != nil {
				// A rejected header: this is a terminal outcome for a
				// real connection (serveConn tears it down), so stop
				// driving this input further -- there is nothing more
				// to decode after an error.
				return
			}
			if token == nil {
				// "Need more data": with atEOF=false there is nothing
				// more this loop can feed it, so this input is
				// exhausted as far as framing goes.
				return
			}
			if advance == 0 {
				t.Fatalf("splitBMPMessage returned a non-nil token with advance=0 (would not make progress)")
			}

			// Exactly what serveConn does with each framed token: hand
			// it to this package's own panic-recovering message
			// decoder. This must not panic (parseBMPMessagePreservingPartial
			// has its own recover specifically so a malicious frame
			// can't take the connection's goroutine down -- this fuzz
			// target is also what proves that recover actually works)
			// or hang regardless of what bytes are inside the frame
			// splitBMPMessage accepted.
			_, _ = parseBMPMessagePreservingPartial(token)

			remaining = remaining[advance:]
		}
	})
}
