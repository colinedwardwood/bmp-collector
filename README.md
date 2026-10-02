# bmp-collector

[![CI](https://github.com/colinedwardwood/bmp-collector/actions/workflows/ci.yml/badge.svg)](https://github.com/colinedwardwood/bmp-collector/actions/workflows/ci.yml)

> **Status (2026-10-02, v0.1.2): hardened library, not device-validated.**
> This started as a spike (2026-09-25) and has since been through four
> rounds of adversarial review/independent re-verification. The first two
> found and fixed two CRITICAL bugs (a framing DoS and a process-crashing
> panic); a third, 7-persona round against v0.1.0 found and fixed six
> more real issues -- most notably another CRITICAL one: per-connection
> and per-message resource caps were each sound in isolation, but their
> *product* was not, letting ~100-150 ordinary, individually-compliant
> connections collectively OOM a memory-limited process (reproduced
> against a container with a tight memory limit before fixing, and
> reproduced fixed after -- see "Aggregate buffer budget" below). A
> fourth round -- independent re-verification of that third round's fixes
> against v0.1.1 -- found two more real, confirmed gaps (tracked as
> [issue #27](https://github.com/colinedwardwood/alloy-network-collector/issues/27)),
> both now fixed in this release: (1) `parseBMPMessagePreservingPartial`'s
> panic recovery used to discard the very Header/PeerHeader it exists to
> preserve whenever gobgp's own unchecked slice indexing panicked on a
> truncated body -- fixed by decoding Header/PeerHeader first and scoping
> the recovery to only the body decode; (2) the `-max-buffered-bytes`
> default (64MiB) left zero real headroom against the container memory
> limits it was advertised as safe for -- lowered to 16MiB, with an
> explicit container-sizing rule now documented on the flag and in
> "Aggregate buffer budget" below. CI
> (build/vet/fmt/race-tested unit tests/lint/govulncheck), a real
> multi-stage Docker build, decode test coverage for all 7 RFC 7854
> message types, and a fuzz target over the framing+decode path remain
> in place and green. It is no longer "exploratory, don't build on it"
> -- but it has **still never been run against a real router**
> (Cisco/Juniper/Arista/FRR/BIRD), every decode test is a
> self-serialize/self-parse round trip through gobgp's own encoder (see
> "Open questions"), and it still has no transport security. Read "Open
> questions" before depending on this for production traffic.

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
  own goroutine that reads it via `readOneBMPMessage` (which applies this
  package's own header validation -- `decodeAndValidateBMPHeader`, shared
  with the directly tested/fuzzed `splitBMPMessage` bufio.SplitFunc below
  -- plus the aggregate buffer-budget admission control, see next bullet)
  one message at a time. Each framed message goes to
  `parseBMPMessagePreservingPartial` (this package's own panic-recovering
  decode, forwarding a partial record -- Header/PeerHeader, even if Body
  failed -- for every RFC 7854 message type) and then to the caller's
  `Callback` (recovered from panics; see `safeInvokeCallback`). The accept
  loop tolerates transient `Accept()` errors, and each connection is
  subject to a concurrent-connection cap, an idle read deadline, and TCP
  keepalive. No dependency on `go.opentelemetry.io/collector/receiver` --
  the shape mirrors it (so it can later become a real `receiver.Receiver`
  or an Alloy component) without hard-depending on it.
  - **Aggregate buffer budget (`readOneBMPMessage`, `WithMaxBufferedBytes`,
    default 16MiB).** Fix for the second round's CRITICAL finding: the
    per-connection cap (`WithMaxConnections`, default 1024) and the
    per-message cap (`maxBMPMessageSize`, 1MiB) are each a sound bound in
    isolation, but their *product* -- up to 1024 connections times 1MiB
    each -- is not. ~100-150 ordinary, individually-compliant connections
    each sending one ~900KB message (well under both existing caps) were
    enough to OOM-kill a container limited to 64MB, reproduced before
    this fix landed. `readOneBMPMessage` acquires each message's declared
    length from a collector-wide `golang.org/x/sync/semaphore.Weighted`
    before allocating or reading any of its body, into a fresh
    message-sized buffer (not a connection-lifetime one -- see below);
    `serveConn` releases that reservation once the message has been fully
    decoded and handed to the callback (or the connection tears down with
    one still pending). That bounds total buffered bytes by the budget
    regardless of how many connections are open. Each connection gets its
    own cancellable child context so a connection blocked waiting on an
    exhausted budget is released by `Shutdown` the same way a connection
    blocked in `Read` already was.
    - **Default lowered from 64MiB to 16MiB, with an explicit sizing
      rule (issue #27 follow-up).** Independent re-verification found the
      original 64MiB default had *zero* real headroom against the exact
      "fits a 64MB container" framing its own doc comment used: the
      specific claim "survives a synchronized 150-connection burst at a
      64MB-limited container with default settings" did not reproduce --
      it needed either a container closer to 160MB+ or artificially
      staggered (20ms-spaced) connection arrivals to avoid an OOM-kill.
      Root cause: the budget bounds only what this package knowingly
      admits into message buffers; it has no way to account for the Go
      runtime's own baseline heap, per-connection goroutine/stack
      overhead, or the transient overshoot a synchronized burst of
      concurrent large messages causes during ordinary GC lag. The new
      16MiB default is this repo's own already-verified-safe value (see
      "What's been verified" below -- the exact figure the original
      container repro used successfully, repeatably, against a real
      64MB limit) rather than a fresh guess, and leaves the budget at
      1/8th of a 128MB container instead of flush against a 64MB one.
      **Sizing rule, wherever this is tuned:** the container/process
      memory limit should exceed `-max-buffered-bytes`/
      `WithMaxBufferedBytes` by **at least 2x, or +100MB, whichever is
      larger** (e.g. the 16MiB default implies at least a ~117MB limit:
      16MiB+100MB exceeds 2x16MiB, so +100MB is the binding term)
      to leave room for the runtime/goroutine overhead above -- this is
      now stated on the `-max-buffered-bytes` flag's own `-help` text as
      well as here.
  - **Why not `bufio.Scanner`.** An earlier version of this exact fix kept
    the original `bufio.Scanner`-based framing and wrapped its
    `bufio.SplitFunc` with the same admission control. That bounded the
    *rate* new buffering could start, but not *steady-state* memory: a
    `Scanner`'s internal buffer only ever grows, never shrinks, so any
    connection that ever received one large message permanently retained
    that much capacity for the rest of its lifetime -- and BMP sessions
    are long-lived by design (RFC 7854: one connection per monitored
    router, not per message), so this still let steady-state memory
    approach `connections * maxMessageSize` once enough distinct,
    otherwise-idle connections had each sent one such message (confirmed
    in testing: live heap still reached 150+MB against a 16MiB budget
    under the full many-long-lived-connections repro). `readOneBMPMessage`
    reads each message into its own freshly-allocated, message-sized
    buffer instead, which becomes garbage -- and collectible -- the
    moment that one message is done, regardless of how long the
    connection stays open afterward. `splitBMPMessage` is kept, unchanged,
    purely as the directly tested/fuzzed definition of this package's
    framing-validation rules (see `fuzz_test.go`); production reads no
    longer go through a `bufio.Scanner` at all.
  - **`parseBMPMessagePreservingPartial`.** Fix for two issues together:
    (1) full-record loss -- gobgp's own `bmp.ParseBMPMessage` discards the
    already-decoded Header/PeerHeader (returns `nil, err`) for every
    message type *except* `BMP_MSG_ROUTE_MONITORING` when the
    type-specific Body fails to parse; this function reimplements the
    same decode sequence with gobgp's exported pieces and always forwards
    the partial message, for every type. (2) panic recovery -- gobgp's own
    internal decode has a `recover()`, but reimplementing it with exported
    calls steps outside that recover, and this decodes fully untrusted
    wire bytes, so this function has its own.
    - **Panic recovery is scoped to only the Body decode (issue #27
      follow-up).** An earlier version of this function wrapped its
      *entire* body in one `recover()` that unconditionally discarded
      Header/PeerHeader (set `msg = nil`) on any panic -- which defeated
      fix (1) above on exactly the panic path. gobgp's own
      `BMPBody.ParseBody` implementations do unchecked slice indexing
      into the variable-length wire body with no bounds checking of
      their own (confirmed in `github.com/osrg/gobgp/v3`'s
      `pkg/packet/bmp/bmp.go`: `BMPStatisticsReport.ParseBody`'s
      `data[0:4]`, `BMPPeerUpNotification.ParseBody`'s `data[:16]` /
      `data[12:16]`) -- so a trivial truncated/short body after an
      otherwise fully-present header and 42-byte peer header panics
      *inside gobgp's code*, and the old recover() handler threw away
      the Header/PeerHeader that had, by that point, already decoded
      successfully -- the opposite of what this function exists to do.
      The shipped regression test at the time
      (`TestDecode_StatisticsReportPartialBodyForwardsPeerIdentity`) only
      ever corrupted a TLV length deep inside the body, which gobgp
      turns into a graceful (non-panicking) error -- so it never
      exercised the panic path at all. Fixed by decoding Header, then
      PeerHeader (both fixed-size, and both now guarded by this
      function's own explicit length checks, not a recover) into `msg`
      *before* ever calling the type-specific Body decode, and scoping
      the `recover()` to only that last, riskier call
      (`parseBMPMessageBody`) -- so a panic there still returns the
      already-captured `msg`, exactly like the graceful-error case.
      Regression tests:
      `TestParseBMPMessagePreservingPartial_TruncatedStatisticsReportBodyPanicsButPreservesPeerHeader`
      and
      `TestParseBMPMessagePreservingPartial_TruncatedPeerUpNotificationBodyPanicsButPreservesPeerHeader`
      in `collector_fixes_test.go`, each with a precondition check
      confirming the corrupted fixture still panics inside gobgp's own
      code directly (independent of this package), so a future gobgp fix
      that adds its own bounds check fails the precondition with a clear
      message instead of either test silently passing for the wrong
      reason.
  - **`ErrorCallback`'s `handshakeComplete` parameter.** Fix for a
    cardinality bug: `onRecord`'s `Record.HandshakeComplete` already
    gated the `router_addr` metric label to stop a port scan or any other
    un-handshaked TCP client from minting its own metric series forever;
    `ErrorCallback` had no equivalent signal at all, so `onError` in
    `cmd/bmp-collector` couldn't apply the same gate. `ErrorCallback` now
    carries the same boolean `Record.HandshakeComplete` does.
  - **Start's ctx-watcher goroutine is now tracked in the Collector's
    wait group**, closing a goroutine leak: previously, for any caller
    that calls `Shutdown` without first (or ever) cancelling the `ctx`
    passed to `Start` -- the common case, including every test in this
    package -- that goroutine parked on `<-ctx.Done()` forever,
    unaccounted for by `Shutdown`'s wait. A `shutdownCh` internal to the
    Collector now wakes it on `Shutdown` regardless of `ctx`'s state.
- **`collector_test.go`** — the original end-to-end test plus the two
  CRITICAL-bug regression tests and the panic-recovery/error-callback/
  logger-option tests: starts a real `Collector` on a loopback TCP port,
  dials in as a router would, writes serialized BMP messages, and asserts
  correct decode, correct teardown on malformed input, and that a
  panicking `Callback` on one connection never takes another connection
  (or the process) down with it.
- **`collector_fixes_test.go`** — regression tests for the second
  adversarial-review round: a 20-cycle Start/Shutdown goroutine-count test
  for the leak fix; for the aggregate-memory fix, a deterministic
  `readOneBMPMessage` acquire/block/release test over an in-memory
  `net.Pipe`, an end-to-end test that `Shutdown` unblocks a connection
  parked on an exhausted buffer budget, and a steady-state memory test
  (~100 long-lived, otherwise-idle connections that each sent one
  maximum-size message must leave live heap within a small multiple of
  the configured budget, not anywhere near `connections * maxMessageSize`
  -- the regression test for the bufio.Scanner-retention pitfall
  described above). Also holds the issue #27 follow-up round's two
  panic-recovery regression tests
  (`TestParseBMPMessagePreservingPartial_TruncatedStatisticsReportBodyPanicsButPreservesPeerHeader`,
  `TestParseBMPMessagePreservingPartial_TruncatedPeerUpNotificationBodyPanicsButPreservesPeerHeader`)
  -- see "`parseBMPMessagePreservingPartial`" above.
- **`fixtures_test.go`** — one wire-serialized fixture per RFC 7854 §4.2
  message type (RouteMonitoring, StatisticsReport, PeerUpNotification,
  PeerDownNotification, Initiation, Termination, RouteMirroring), each
  built via gobgp's own constructors, plus a `TestDecode_*` test per type
  that asserts it decodes correctly end to end through the real
  `Collector`/TCP/`splitBMPMessage`/`parseBMPMessagePreservingPartial`
  path -- not just RouteMonitoring, which is all the original test suite
  covered -- plus a partial-record-forwarding regression test for
  StatisticsReport paralleling RouteMonitoring's.
- **`fuzz_test.go`** — `FuzzSplitAndParseBMPMessage`, a native Go fuzz
  target over exactly the two-call sequence `serveConn` drives on every
  byte a connection sends (`splitBMPMessage` then
  `parseBMPMessagePreservingPartial`), seeded with one fixture per message
  type plus the literal byte patterns from the two original CRITICAL bug
  fixes (`Length=0`, an invalid version byte) and a few adjacent boundary
  cases (truncated header, mid-message truncation, oversized `Length`).
  Run locally with `go test -fuzz FuzzSplitAndParseBMPMessage -fuzztime
  45s`: 45s / ~13.5M executions / 0 crashes as of this writing. Run it
  yourself with `go test -fuzz FuzzSplitAndParseBMPMessage`.
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
  `network-topology-exporter`'s existing dual-output precedent. The
  library's connection/resource-limit options are now exposed as flags
  too: `-max-connections` (default 1024), `-idle-timeout` (default 10m),
  `-tcp-keepalive` (default 30s), and `-max-buffered-bytes` (default
  16MiB, the aggregate buffer budget above) -- previously only reachable
  by a Go caller of the library, not tunable on this binary without a
  rebuild. `-max-connections` and `-max-buffered-bytes` are the two
  operator-facing knobs for the aggregate-memory fix: the budget bounds
  total buffering regardless of connection count on its own, and a lower
  `-max-connections` additionally shrinks the worst case before the
  budget is ever what's doing the bounding. `-max-buffered-bytes`'s own
  `-help` text also states the sizing rule for the container/process
  memory limit above it (at least 2x, or +100MB, whichever is larger --
  see "Aggregate buffer budget" above).

## What's been verified

- `go build ./...`, `go vet ./...`, `gofmt -l .` (clean), and
  `golangci-lint run ./...` (0 issues, `.golangci.yml`) are all clean.
- `go test ./... -race -count=1 -cover` passes. Current coverage: **84.5%**
  of statements in the `bmpcollector` package (`cmd/bmp-collector` has no
  unit tests yet -- it's a thin flag-parsing/wiring main, exercised only
  manually/via the Docker smoke test described under "Usage").
- **The aggregate-memory/OOM fix was verified before/after, against a
  real container memory limit, not just unit tests:** with a 64MB
  `--memory` limit, ~150 concurrent connections each sending one ~900KB
  BMP-framed message OOM-killed the unpatched image (`OOMKilled: true`,
  exit code 137) within seconds; the identical repro against the patched
  image completed without the container being OOM-killed, repeatably
  across multiple rounds, using `-max-buffered-bytes=16MiB` against that
  64MB limit.
- **Follow-up (issue #27): the *default*-configured collector re-tested
  against the sizing rule this README now states.** Independent
  re-verification found the *original* 64MiB default gave the 64MB
  container repro above zero real headroom -- the specific claim that
  default settings survived a synchronized 150-connection burst at a
  64MB limit did not reproduce; it needed either a ~160MB+ container or
  artificially staggered connection arrivals. The default is now 16MiB
  (see "Aggregate buffer budget" above). Re-run with the *default*
  `-max-buffered-bytes`/`-max-connections` (no manual tuning), same
  synchronized-150-connection/~900KB-message burst shape, against three
  container sizes:
  - **128MB** (inside this README's own 128-256MB target range): not
    OOM-killed; live RSS settled at ~42.6MiB (33% of the limit).
  - **~117MB** (this README's own stated minimum for the 16MiB default
    -- `max(2x16MiB, 16MiB+100MB)`): not OOM-killed across three
    back-to-back/overlapping burst rounds (up to ~300-450 connections
    transiently open at once); live RSS settled at ~50.4MiB (43% of the
    limit).
  - **64MB** (the *original* repro's own container size, i.e. well
    below this new default's stated minimum, kept purely to show the
    improvement at a fixed limit): also not OOM-killed -- live RSS
    reached ~47.2MiB (74% of the limit, the closest margin of the
    three, as expected for a limit below the stated minimum) -- a
    concrete improvement over the old 64MiB default, which needed a
    ~160MB+ container or staggered arrivals to survive the identical
    burst at this same 64MB limit. This is not a claim that 64MB is a
    recommended limit for the new default; it demonstrates margin, not
    a new minimum.
- **The two issue #27 panic-recovery repros were re-attempted directly
  against the fixed `parseBMPMessagePreservingPartial` and now preserve
  peer identity.** A PeerUpNotification and a StatisticsReport, each
  with a deliberately truncated body after an otherwise fully-present
  42-byte peer header (the exact corruption shapes the independent
  re-verification found -- see "`parseBMPMessagePreservingPartial`"
  above), both still panic inside gobgp's own code as before (confirmed
  by each test's own precondition check), but the returned message now
  carries a non-nil `PeerHeader` with the correct `PeerAddress`/`PeerAS`
  instead of `nil` -- regression tests
  `TestParseBMPMessagePreservingPartial_TruncatedStatisticsReportBodyPanicsButPreservesPeerHeader`
  and
  `TestParseBMPMessagePreservingPartial_TruncatedPeerUpNotificationBodyPanicsButPreservesPeerHeader`
  in `collector_fixes_test.go`. Re-ran the full suite after both fixes:
  `go build ./...`, `go vet ./...`, `gofmt -l .`, and
  `golangci-lint run ./...` all still clean; `go test ./... -race
  -count=1 -cover` still green (84.5% coverage, unchanged); `govulncheck
  ./...` still reports only the same already-tracked, not-reachable
  GO-2026-4736 (see "Known-unpatched upstream advisory" below --
  unaffected by either fix); `FuzzSplitAndParseBMPMessage` re-run for
  35s (~10.2M executions) with zero crashes.
- Every RFC 7854 §4.2 message type has a passing decode test (see
  `fixtures_test.go`), not just RouteMonitoring, including a
  partial-record-forwarding case for a type other than RouteMonitoring
  (StatisticsReport).
- A 20-cycle repeated Start/Shutdown test asserts Go's live goroutine
  count returns to baseline after every single cycle, using a
  never-cancelled `context.Background()` -- the exact condition that grew
  the count unboundedly (2->22, 1->21 over 20 cycles in two runs) before
  the ctx-watcher goroutine-leak fix.
- `FuzzSplitAndParseBMPMessage` ran for 45s (~13.5M executions) locally
  with zero crashes, over a seed corpus that includes both known-good
  fixtures and the exact malicious patterns the two original CRITICAL
  bugs were found with -- now exercising
  `parseBMPMessagePreservingPartial` (this package's own decode wrapper)
  rather than calling gobgp's `bmp.ParseBMPMessage` directly, so the fuzz
  target covers the same panic-recovery path production traffic does.
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
  concurrent-connection cap, a per-connection idle read deadline,
  OS-level TCP keepalive, and an aggregate buffer-budget admission
  control (`WithMaxConnections`/`WithIdleTimeout`/`WithTCPKeepAlive`/
  `WithMaxBufferedBytes`, all with prototype-stage default values and
  now all exposed as `cmd/bmp-collector` flags too), but backlog tuning
  and behavior under an actual router-side reconnect storm are still
  untested against anything but the loopback-socket test suite and the
  one-shot container-memory-limit repro described above.
- **Known-unpatched upstream advisory: GO-2026-4736 -- tracked, not
  demonstrated reachable via this repo's actual import surface.**
  `govulncheck ./...` flags
  [GO-2026-4736](https://pkg.go.dev/vuln/GO-2026-4736) ("GoBGP
  vulnerable to a denial of service via the NEXT_HOP path attribute") in
  `github.com/osrg/gobgp/v3@v3.37.0`, with no fixed version available yet
  (`Fixed in: N/A`). govulncheck's static call-graph trace reports a
  path through this package's own `bgp.ParseBGPMessage` call (now inside
  `parseBMPMessagePreservingPartial`, the fix for bug #3 below), which
  looks at first glance like it confirms reachability of the advisory's
  actual vulnerable code. It doesn't: the advisory's vulnerable code
  lives in gobgp's `pkg/server` (gobgp acting as a full BGP speaker/BMP
  *client* -- see "Why this exists" above for why this repo doesn't
  import that package at all, only `pkg/packet/bmp` + `pkg/packet/bgp`,
  confirmed via `go list -deps`, which decode wire bytes and don't speak
  BGP sessions themselves). A second-round adversarial review (security
  persona) traced the advisory's actual vulnerable code path, then fed
  the upstream advisory's own malformed-input regression-test bytes
  through this repo's real call path end to end (`splitBMPMessage` →
  `parseBMPMessagePreservingPartial` → the inner `bgp.ParseBGPMessage`
  call) and observed no panic, no hang, and no resource blowup --
  consistent with the vulnerable code genuinely not being on this
  repo's import surface, i.e. govulncheck's reachability trace here is
  an over-approximation (a known class of false positive for this tool:
  it flags a module-level symbol as reachable from any call into the
  same package, not only from a call path through the actually-affected
  function). **Net: this advisory is tracked (watch for a gobgp patch
  release and bump the dependency the moment one ships, since the
  specific vulnerable function could change and the question would need
  re-checking), not confirmed live/exploitable via how this repo
  actually uses gobgp today.** The `govulncheck` CI job stays
  informational (`continue-on-error`) on this basis, pending either a
  gobgp patch or an upstream advisory narrowing that changes this
  analysis.
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

Connection/resource limits are tunable without a rebuild: `-max-connections`
(default 1024), `-idle-timeout` (default 10m), `-tcp-keepalive` (default
30s), and `-max-buffered-bytes` (default 16MiB -- the aggregate buffer
budget described under "What's built"). **Whatever `-max-buffered-bytes`
is set to, size the container/process memory limit to exceed it by at
least 2x, or +100MB, whichever is larger** (e.g. the 16MiB default implies
at least a ~117MB limit) -- this budget bounds only what the collector
itself will knowingly buffer, not the Go runtime's own baseline footprint,
per-connection goroutine/stack overhead, or the transient overshoot a
synchronized burst of large messages can cause during GC lag; a limit set
right at (or only slightly above) the budget has been observed to still
OOM under such a burst. A memory-constrained deployment may additionally
want to lower `-max-connections` below its generous default.

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
