# bmp-collector

> **SPIKE / PROTOTYPE — dated 2026-09-25.** This is exploratory, not a
> production release. It has been built and tested locally (see "What's
> been verified" below), but it has **not** been run against real router
> hardware, has no security/auth story, and its API shape is expected to
> change. See "Open questions" before depending on this for anything real.

A minimal BMP (BGP Monitoring Protocol, [RFC 7854](https://www.rfc-editor.org/rfc/rfc7854)) collector:
it accepts inbound TCP sessions from routers acting as BMP clients, decodes
every BMP message (route monitoring, statistics reports, peer up/down,
initiation/termination, route mirroring), and pushes decoded records through
a callback — in the same `Start(ctx)/Shutdown(ctx)` + callback shape used by
this effort's other two collectors ([`gnmi-collector`](https://github.com/colinedwardwood/gnmi-collector),
[`flow-collector`](https://github.com/colinedwardwood/flow-collector)).

## Why this exists

This was built as part of a small research effort into three network
telemetry protocols (gNMI, flow/NetFlow-IPFIX-sFlow, and BMP) with an eye
toward eventually feeding [Grafana Alloy](https://github.com/grafana/alloy)
or an OpenTelemetry Collector distribution. The research question for BMP
specifically was: *does a usable Go BMP decoding library already exist, or
does this project need to hand-write RFC 7854 wire framing and a BGP UPDATE
parser from scratch?*

**Finding: a usable library exists.** `github.com/osrg/gobgp/v3/pkg/packet/bmp`
(plus its `pkg/packet/bgp` sibling) is a framework-independent, Apache-2.0,
dependency-light package that already implements the full RFC 7854 message
set in both directions, including a ready-made `bufio.SplitFunc`
(`bmp.SplitBMP`) for framing a raw TCP byte stream into discrete messages.
The inner BGP UPDATE inside route-monitoring/peer-up/peer-down messages
decodes via gobgp's own mature BGP packet parser — no separate integration
work needed. That reclassified BMP from "protocol decode is the hard,
unknown part" to "protocol decode is solved off the shelf; the work is
wiring it into a clean library+binary," which is why this repo contains a
working prototype rather than research-only notes.

Note on gobgp's *other* BMP code: `gobgp`'s `pkg/server/bmp.go` is **not** a
monitoring station — it's gobgp acting as a BMP *client*, dialing out to
push its own RIB to an external monitor. This project instead imports only
`pkg/packet/bmp` + `pkg/packet/bgp` (the wire-format codec), and implements
its own TCP accept/serve loop on top of it — see `collector.go`.

## What's built

- **`collector.go`** — the core library. `bmpcollector.New(listenAddr, cb, opts...)`
  returns a `*Collector` with `Start(ctx)`/`Shutdown(ctx)`. `Start` binds a
  TCP listener and spawns an accept loop; each accepted connection gets its
  own goroutine running a `bufio.Scanner` with `bmp.SplitBMP` as the split
  function, feeding each framed message to `bmp.ParseBMPMessage` and then to
  the caller's `Callback`. No dependency on
  `go.opentelemetry.io/collector/receiver` — the shape mirrors it (so it can
  later become a real `receiver.Receiver` or an Alloy component) without
  hard-depending on it.
- **`collector_test.go`** — an end-to-end test: it starts a real `Collector`
  on a loopback TCP port, dials in as a router would, writes two
  back-to-back serialized BMP RouteMonitoring messages in a single `Write`
  (exercising `bmp.SplitBMP`'s stream framing, not just a single decode
  call), and asserts both are decoded correctly — peer address/AS, the inner
  BGP UPDATE's NLRI and path attributes, all read back via the ordinary
  `bmp`/`bgp` package types.
- **`cmd/bmp-collector/`** — a small binary wrapping the library: BMP TCP
  listener (`-listen`, default `:1790`), a `bmp.messages_total` /
  `bmp.decode_errors_total` counter pair reported both via OTLP/HTTP push
  (`-otlp-endpoint`, default-off) and a Prometheus `/metrics` endpoint
  (`-metrics-addr`, default `:9464`) — matching
  `network-topology-exporter`'s existing dual-output precedent.

## What's been verified

- `go build ./...` and `go vet ./...` are clean.
- `go test ./...` passes, including the end-to-end TCP decode test above.
- The synthetic test message is built via gobgp's **own constructors**
  (`bmp.NewBMPPeerHeader`, `bmp.NewBMPRouteMonitoring`,
  `bgp.NewBGPUpdateMessage`, etc.) — i.e. this is a self-serialize/
  self-parse round trip through the library's own encoder and decoder.

## Open questions / what this prototype does *not* prove

- **No real-router bytes tested.** The only decode test exercised is a
  self-generated synthetic message round-tripped through gobgp's own
  encoder and decoder. That can't catch a discrepancy between gobgp's
  encoder and how a real Cisco/Juniper/Arista/FRR router actually encodes
  BMP on the wire. Before trusting this against production routers: capture
  or find real BMP pcaps (public route collectors, vendor docs, or a lab
  FRR/BIRD instance configured to speak BMP) and re-run the decode test
  against those bytes.
- **No transport security.** RFC 7854 defines no authentication or
  encryption for BMP; this prototype's TCP listener accepts any connection
  on the configured port. A real deployment needs network ACLs or a
  TLS-terminating proxy in front of it — this is a deployment/docs concern,
  not something the code should try to solve itself yet.
- **API surface re-exposes gobgp's own types.** `Record.Message` and
  `Record.PeerHeader` are `bmp.BMPMessage`/`bmp.BMPPeerHeader` directly, not
  project-owned DTOs. That's fast for a spike but binds every consumer to
  gobgp's type shapes; worth revisiting once/if this is wired into a real
  OTel receiver or Alloy component, ideally consistently with whatever
  `gnmi-collector`/`flow-collector` settle on for their own decoded-record
  types.
- **Reconnect/backpressure under load is untested.** BMP is one long-lived
  TCP session per monitored router. This prototype's accept/serve loop has
  no explicit connection limit, backlog tuning, or behavior documented for
  a router-side reconnect storm.
- **Metric set is minimal.** `cmd/bmp-collector` only counts messages by
  type and decode errors. A real deployment would likely want per-AFI/SAFI
  route counts, per-peer session-state gauges (from PeerUp/PeerDown), and
  parsed route-monitoring NLRI/attribute detail — none of that is built
  yet.
- **gobgp/v3 dependency footprint.** `pkg/packet/bmp` + `pkg/packet/bgp`
  pull in only Go stdlib transitively (verified via `go list -deps`), but
  pinning them ties this repo's release cadence to gobgp's upstream. Not a
  blocker today; worth watching if gobgp ships a breaking change to that
  package.
- Two other reference points, not evaluated in depth because gobgp's
  package already cleared the bar: `sbezverk/gobmp` (a full integrated BMP
  collector binary, useful as a reference implementation, not a reusable
  library) and `bgpfix/bgpfix/bmp` (a lower-level alternative). Worth a look
  if gobgp's BMP package ever turns out to have a real gap (an AFI/SAFI or
  TLV it doesn't handle).

## Usage

```
go run ./cmd/bmp-collector -listen :1790 -metrics-addr :9464
```

Point a BMP-speaking router (or a test client) at `:1790`. Metrics are on
`http://localhost:9464/metrics`. Pass `-otlp-endpoint host:4318` to also
push via OTLP/HTTP (e.g. to a Grafana Alloy `otelcol.receiver.otlp`).

## License

Apache License 2.0 — see [LICENSE](LICENSE). Chosen deliberately over
AGPL (used by the unrelated `network-topology-exporter` project) so this
can be embedded into Apache-2.0 projects like Grafana Alloy or an OTel
Collector distribution without license friction.
