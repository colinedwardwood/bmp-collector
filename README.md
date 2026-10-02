# bmp-collector

[![CI](https://github.com/colinedwardwood/bmp-collector/actions/workflows/ci.yml/badge.svg)](https://github.com/colinedwardwood/bmp-collector/actions/workflows/ci.yml)

> **Status (2026-10-02, v0.1.0): hardened library, not device-validated.**
> This started as a spike (2026-09-25) and has since been through two
> rounds of adversarial review (two CRITICAL bugs -- a framing DoS and a
> process-crashing panic -- found and fixed), gained CI (build/vet/fmt/
> race-tested unit tests/lint/govulncheck), a real multi-stage Docker
> build, decode test coverage for all 7 RFC 7854 message types, and a
> fuzz target over the exact framing path the CRITICAL bugs lived in. It
> is no longer "exploratory, don't build on it" -- but it has **still
> never been run against a real router** (Cisco/Juniper/Arista/FRR/BIRD),
> every decode test is a self-serialize/self-parse round trip through
> gobgp's own encoder (see "Open questions"), and it still has no
> transport security. Read "Open questions" before depending on this for
> production traffic.

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
  own goroutine running a `bufio.Scanner` with this package's own
  `splitBMPMessage` (a validating wrapper around gobgp's header decode --
  see the fix notes on that function) as the split function, feeding each
  framed message to `bmp.ParseBMPMessage` and then to the caller's
  `Callback` (recovered from panics; see `safeInvokeCallback`). The accept
  loop tolerates transient `Accept()` errors, and each connection is
  subject to a concurrent-connection cap, an idle read deadline, and TCP
  keepalive. No dependency on `go.opentelemetry.io/collector/receiver` --
  the shape mirrors it (so it can later become a real `receiver.Receiver`
  or an Alloy component) without hard-depending on it.
- **`collector_test.go`** — the original end-to-end test plus the two
  CRITICAL-bug regression tests and the panic-recovery/error-callback/
  logger-option tests: starts a real `Collector` on a loopback TCP port,
  dials in as a router would, writes serialized BMP messages, and asserts
  correct decode, correct teardown on malformed input, and that a
  panicking `Callback` on one connection never takes another connection
  (or the process) down with it.
- **`fixtures_test.go`** — one wire-serialized fixture per RFC 7854 §4.2
  message type (RouteMonitoring, StatisticsReport, PeerUpNotification,
  PeerDownNotification, Initiation, Termination, RouteMirroring), each
  built via gobgp's own constructors, plus a `TestDecode_*` test per type
  that asserts it decodes correctly end to end through the real
  `Collector`/TCP/`splitBMPMessage`/`bmp.ParseBMPMessage` path -- not just
  RouteMonitoring, which is all the original test suite covered.
- **`fuzz_test.go`** — `FuzzSplitAndParseBMPMessage`, a native Go fuzz
  target over exactly the two-call sequence `serveConn` drives on every
  byte a connection sends (`splitBMPMessage` then `bmp.ParseBMPMessage`),
  seeded with one fixture per message type plus the literal byte patterns
  from the two CRITICAL bug fixes (`Length=0`, an invalid version byte)
  and a few adjacent boundary cases (truncated header, mid-message
  truncation, oversized `Length`). Run locally with
  `go test -fuzz FuzzSplitAndParseBMPMessage -fuzztime 45s`: 45s / ~13.4M
  executions / 0 crashes as of this writing. Run it yourself with
  `go test -fuzz FuzzSplitAndParseBMPMessage`.
- **`.github/workflows/ci.yml`** — `go build`, `go vet`, a `gofmt -l`
  formatting gate, `go test ./... -race -count=1 -cover`, `golangci-lint`
  (config: `.golangci.yml`), and an informational (non-blocking)
  `govulncheck` job -- see "Known-unpatched upstream advisory" below for
  why that job is expected to report a finding today.
- **`Dockerfile`** — multi-stage: `golang:1.27-alpine` builder producing a
  static (`CGO_ENABLED=0`) binary, copied onto
  `gcr.io/distroless/static-debian12:nonroot` (no shell, no package
  manager, runs as a non-root user). `docker build .` produces a runnable
  image; see "Usage" below.
- **`cmd/bmp-collector/`** — a small binary wrapping the library: BMP TCP
  listener (`-listen`, default `:1790`), a `bmp.messages_total` /
  `bmp.decode_errors_total` counter pair reported both via OTLP/HTTP push
  (`-otlp-endpoint`, default-off) and a Prometheus `/metrics` endpoint
  (`-metrics-addr`, default `:9464`) — matching
  `network-topology-exporter`'s existing dual-output precedent.

## What's been verified

- `go build ./...`, `go vet ./...`, `gofmt -l .` (clean), and
  `golangci-lint run ./...` (0 issues, `.golangci.yml`) are all clean.
- `go test ./... -race -count=1 -cover` passes. Current coverage: **81.4%**
  of statements in the `bmpcollector` package (`cmd/bmp-collector` has no
  unit tests yet -- it's a thin flag-parsing/wiring main, exercised only
  manually/via the Docker smoke test described under "Usage").
- Every RFC 7854 §4.2 message type has a passing decode test (see
  `fixtures_test.go`), not just RouteMonitoring.
- `FuzzSplitAndParseBMPMessage` ran for 45s (~13.4M executions) locally
  with zero crashes, over a seed corpus that includes both known-good
  fixtures and the exact malicious patterns the two CRITICAL bugs were
  found with.
- `docker build .` succeeds, and the resulting image starts, binds both
  configured ports, and serves `/metrics` as a non-root user with no
  shell in the image.
- Every synthetic test message (fixtures and fuzz seeds alike) is built
  via gobgp's **own constructors** (`bmp.NewBMPPeerHeader`,
  `bmp.NewBMPRouteMonitoring`, `bgp.NewBGPUpdateMessage`, etc.) — i.e.
  this is a self-serialize/self-parse round trip through the library's
  own encoder and decoder, not a test against bytes a real router
  produced. See "Open questions" below -- this is the main thing that
  still hasn't been validated.

## Open questions / what this prototype does *not* prove

- **No real-router bytes tested.** Every decode test (now covering all 7
  RFC 7854 message types, plus the fuzz corpus) is still a
  self-generated synthetic message round-tripped through gobgp's own
  encoder and decoder. That can't catch a discrepancy between gobgp's
  encoder and how a real Cisco/Juniper/Arista/FRR/BIRD router actually
  encodes BMP on the wire. This was searched for explicitly (as a
  best-effort pass, not a hard requirement) and deliberately **not**
  resolved this round:
  - Wireshark's `SampleCaptures` wiki page hosts a `bmp.pcap` (Init, Peer
    Up, Route Monitoring) — a plausible real/real-ish capture, but the
    wiki page states no explicit license or redistribution terms for it,
    and its provenance (whose router, whether addresses are sanitized)
    isn't documented either. Not committed here on that basis.
  - The `andrediashexa/NOGGlass` project has a `testdata/frr-9.1-bmp-stream.bin`
    fixture described as a real, captured-and-frozen FRR 9.1 BMP stream —
    the best lead found. That project is GPLv3, though, and this repo is
    deliberately Apache-2.0 (see "License" below, and the existing note
    about avoiding exactly this kind of license friction); pulling a
    GPLv3 project's fixture into an Apache-2.0 repo's committed test data
    wasn't a call this pass should make unilaterally.
  - RouteViews/RIPE RIS publish real routing data, but as MRT-format BGP
    dumps or a live Kafka/WebSocket feed (BGPStream's public BMP feed,
    RIS Live) — not static BMP-framed byte fixtures that could be
    vendored into this repo without standing up a stream consumer.
  - **Net: not done.** The lowest-friction realistic path, if/when this
    matters enough to pursue: stand up a lab FRR or BIRD instance
    (Apache-2.0/BSD-compatible, no license question) configured to speak
    BMP to a throwaway listener, capture its actual wire bytes once, and
    commit *that* as a fixture with documented provenance.
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
  TCP session per monitored router. The accept/serve loop now has a
  concurrent-connection cap, a per-connection idle read deadline, and
  OS-level TCP keepalive (`WithMaxConnections`/`WithIdleTimeout`/
  `WithTCPKeepAlive`, all with prototype-stage default values), but
  backlog tuning and behavior under an actual router-side reconnect storm
  are still untested against anything but the loopback-socket test suite.
- **Known-unpatched upstream advisory: GO-2026-4736.** `govulncheck ./...`
  flags [GO-2026-4736](https://pkg.go.dev/vuln/GO-2026-4736) ("GoBGP
  vulnerable to a denial of service via the NEXT_HOP path attribute") in
  `github.com/osrg/gobgp/v3@v3.37.0`, with no fixed version available yet
  (`Fixed in: N/A`). It is reachable from this collector's own decode
  path: govulncheck's call graph traces it through
  `Collector.serveConn` → `bmp.ParseBMPMessage` → `bgp.ParseBGPMessage`,
  i.e. every inbound BMP RouteMonitoring message this collector decodes
  passes through the vulnerable code. This is a supply-chain risk to
  track (watch for a gobgp patch release and bump the dependency the
  moment one ships), not something this repo can fix unilaterally today
  short of vendoring a patched fork of gobgp's `bgp` package.
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

### Directly with Go

```
go run ./cmd/bmp-collector -listen :1790 -metrics-addr :9464
```

Point a BMP-speaking router (or a test client) at `:1790`. Metrics are on
`http://localhost:9464/metrics`. Pass `-otlp-endpoint host:4318` to also
push via OTLP/HTTP (e.g. to a Grafana Alloy `otelcol.receiver.otlp`).

### With Docker

```
docker build -t bmp-collector .
docker run --rm -p 1790:1790 -p 9464:9464 bmp-collector -listen :1790 -metrics-addr :9464
```

The image is a static binary on `distroless/static-debian12:nonroot` --
no shell, no package manager, runs as a non-root user.

### Running the tests / fuzzer

```
go test ./...                              # unit tests
go test ./... -race -count=1 -cover        # as CI runs them
go test -fuzz FuzzSplitAndParseBMPMessage  # fuzz the framing/decode path (Ctrl-C to stop)
```

## License

Apache License 2.0 — see [LICENSE](LICENSE). Chosen deliberately over
AGPL (used by the unrelated `network-topology-exporter` project) so this
can be embedded into Apache-2.0 projects like Grafana Alloy or an OTel
Collector distribution without license friction.
