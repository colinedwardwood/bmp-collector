// Command bmp-collector is a thin binary wrapper around the bmpcollector
// library: it listens for inbound BMP (RFC 7854) TCP sessions from
// routers, decodes every message, counts them by type, and exposes those
// counts two ways -- pushed as OTLP metrics (default) and served on a
// Prometheus /metrics endpoint -- matching network-topology-exporter's
// existing dual-output precedent.
//
// See ../../README.md for current status.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	bmpcollector "github.com/colinedwardwood/bmp-collector"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

func main() {
	var (
		listenAddr   = flag.String("listen", ":1790", "TCP address to accept inbound BMP sessions from routers on")
		metricsAddr  = flag.String("metrics-addr", ":9464", "address to serve the Prometheus /metrics endpoint on")
		otlpEndpoint = flag.String("otlp-endpoint", "", "OTLP/HTTP metrics endpoint (e.g. alloy:4318); OTLP push is disabled when empty")
		otlpInsecure = flag.Bool("otlp-insecure", true, "use an unencrypted (http, not https) connection to -otlp-endpoint")
		pushInterval = flag.Duration("otlp-push-interval", 15*time.Second, "how often to push accumulated counters to -otlp-endpoint")

		// Connection/resource limits. These were previously only
		// reachable by a Go caller of the bmpcollector library
		// (WithMaxConnections/WithIdleTimeout/WithTCPKeepAlive/
		// WithMaxBufferedBytes) with no way to tune them on this
		// binary short of a rebuild. -max-connections and
		// -max-buffered-bytes together are also the two operator-facing
		// mitigations for the aggregate-memory/OOM bug (see
		// bmpcollector.defaultMaxBufferedBytes): the library's own
		// admission control bounds aggregate buffering regardless of
		// connection count, and lowering -max-connections additionally
		// shrinks the worst case before that budget is ever the thing
		// doing the bounding -- an operator who knows their expected
		// peer count and available memory should tune both together.
		//
		// -max-buffered-bytes' own default was lowered from 64MiB to
		// 16MiB (issue #27 follow-up): independent re-verification found
		// the old default left zero headroom against the exact
		// container-memory-limit size ("64MiB budget fits a 64MB
		// container") its own doc comment advertised as safe -- a
		// synchronized burst of concurrent large messages could
		// transiently overshoot that budget during ordinary GC lag,
		// since neither the budget nor the container limit it was sized
		// against ever accounted for the Go runtime's own baseline
		// footprint or per-connection goroutine/stack overhead. See the
		// flag's own help text below and README.md for the margin this
		// collector now explicitly recommends between this value and
		// the container/process memory limit.
		maxConnections   = flag.Int("max-connections", 1024, "maximum concurrent router connections this collector will accept; <= 0 disables the cap")
		idleTimeout      = flag.Duration("idle-timeout", 10*time.Minute, "how long a connection may go without any data before it is closed; <= 0 disables the idle timeout")
		tcpKeepAlive     = flag.Duration("tcp-keepalive", 30*time.Second, "OS-level TCP keepalive probe period for accepted connections; <= 0 disables keepalive")
		maxBufferedBytes = flag.Int64("max-buffered-bytes", 16<<20, "aggregate byte budget this collector will buffer at once across every connection's in-flight message, regardless of connection count; <= 0 disables the budget (not recommended -- see README.md). IMPORTANT: this budget cannot account for Go runtime/goroutine overhead or a transient burst's GC lag -- size the container/process memory limit to exceed this value by at least 2x, or +100MB, whichever is larger (e.g. 16MiB default -> at least a ~117MB limit: 16MiB+100MB, which exceeds 2x16MiB), or it can still OOM under a synchronized burst of large messages even while staying under its own budget")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := collectorConfig{
		listenAddr:       *listenAddr,
		metricsAddr:      *metricsAddr,
		otlpEndpoint:     *otlpEndpoint,
		otlpInsecure:     *otlpInsecure,
		pushInterval:     *pushInterval,
		maxConnections:   *maxConnections,
		idleTimeout:      *idleTimeout,
		tcpKeepAlive:     *tcpKeepAlive,
		maxBufferedBytes: *maxBufferedBytes,
	}

	if err := run(cfg, logger); err != nil {
		logger.Error("bmp-collector: exiting", "err", err)
		os.Exit(1)
	}
}

// collectorConfig holds every flag run needs, so adding one doesn't grow
// run's own parameter list indefinitely.
type collectorConfig struct {
	listenAddr       string
	metricsAddr      string
	otlpEndpoint     string
	otlpInsecure     bool
	pushInterval     time.Duration
	maxConnections   int
	idleTimeout      time.Duration
	tcpKeepAlive     time.Duration
	maxBufferedBytes int64
}

func run(cfg collectorConfig, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName("bmp-collector"),
	))
	if err != nil {
		return fmt.Errorf("build resource: %w", err)
	}

	var readers []sdkmetric.Option

	// Prometheus /metrics (pull). The prometheus.Exporter is itself an
	// sdkmetric.Reader; promhttp serves whatever the OTel SDK's
	// internal prometheus.Registerer has been fed.
	promExporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("build prometheus exporter: %w", err)
	}
	readers = append(readers, sdkmetric.WithReader(promExporter))

	// OTLP push, default-on when -otlp-endpoint is set (matching
	// network-topology-exporter's own OTLP-first, Prometheus-secondary
	// convention). Left disabled with no endpoint configured so the
	// prototype can be run standalone (e.g. under `go test`/local dev)
	// without a collector to push to.
	var otlpExp sdkmetric.Exporter
	if cfg.otlpEndpoint != "" {
		opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(cfg.otlpEndpoint)}
		if cfg.otlpInsecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		otlpExp, err = otlpmetrichttp.New(ctx, opts...)
		if err != nil {
			return fmt.Errorf("build OTLP metric exporter: %w", err)
		}
		readers = append(readers, sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(otlpExp, sdkmetric.WithInterval(cfg.pushInterval)),
		))
	} else {
		logger.Warn("bmp-collector: -otlp-endpoint not set; OTLP push disabled, serving Prometheus /metrics only")
	}

	mpOpts := append([]sdkmetric.Option{sdkmetric.WithResource(res)}, readers...)
	mp := sdkmetric.NewMeterProvider(mpOpts...)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mp.Shutdown(shutdownCtx); err != nil {
			logger.Error("bmp-collector: meter provider shutdown", "err", err)
		}
	}()

	meter := mp.Meter("github.com/colinedwardwood/bmp-collector")
	inst, err := newInstruments(meter)
	if err != nil {
		return fmt.Errorf("build instruments: %w", err)
	}

	col := bmpcollector.New(cfg.listenAddr, inst.onRecord(logger),
		bmpcollector.WithErrorCallback(inst.onError(logger)),
		bmpcollector.WithLogger(logger),
		bmpcollector.WithMaxConnections(cfg.maxConnections),
		bmpcollector.WithIdleTimeout(cfg.idleTimeout),
		bmpcollector.WithTCPKeepAlive(cfg.tcpKeepAlive),
		bmpcollector.WithMaxBufferedBytes(cfg.maxBufferedBytes),
	)
	if err := col.Start(ctx); err != nil {
		return fmt.Errorf("start collector: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	metricsSrv := &http.Server{Addr: cfg.metricsAddr, Handler: mux}
	go func() {
		logger.Info("bmp-collector: serving /metrics", "addr", cfg.metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("bmp-collector: metrics server failed", "err", err)
		}
	}()

	<-ctx.Done()
	logger.Info("bmp-collector: shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var errs []error
	if err := col.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, fmt.Errorf("collector shutdown: %w", err))
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, fmt.Errorf("metrics server shutdown: %w", err))
	}
	return errors.Join(errs...)
}

// instruments holds the counters this binary reports. It's a thin
// prototype-stage metric set -- see README.md "Open questions" for what a
// production metric surface (per-AFI/SAFI route counts, per-peer session
// state gauges, etc.) would need to add.
type instruments struct {
	messagesTotal    metric.Int64Counter
	decodeErrorTotal metric.Int64Counter
}

func newInstruments(meter metric.Meter) (*instruments, error) {
	messagesTotal, err := meter.Int64Counter("bmp.messages_total",
		metric.WithDescription("BMP messages received, by message_type and router_addr."),
	)
	if err != nil {
		return nil, err
	}
	decodeErrorTotal, err := meter.Int64Counter("bmp.decode_errors_total",
		metric.WithDescription("BMP messages that failed to decode, by router_addr."),
	)
	if err != nil {
		return nil, err
	}
	return &instruments{messagesTotal: messagesTotal, decodeErrorTotal: decodeErrorTotal}, nil
}

func messageTypeLabel(t uint8) string {
	switch t {
	case bmp.BMP_MSG_ROUTE_MONITORING:
		return "route_monitoring"
	case bmp.BMP_MSG_STATISTICS_REPORT:
		return "statistics_report"
	case bmp.BMP_MSG_PEER_DOWN_NOTIFICATION:
		return "peer_down_notification"
	case bmp.BMP_MSG_PEER_UP_NOTIFICATION:
		return "peer_up_notification"
	case bmp.BMP_MSG_INITIATION:
		return "initiation"
	case bmp.BMP_MSG_TERMINATION:
		return "termination"
	case bmp.BMP_MSG_ROUTE_MIRRORING:
		return "route_mirroring"
	default:
		return "unknown"
	}
}

// unidentifiedRouterAddr is the router_addr label value used for any
// message received before its connection has completed a valid BMP
// handshake (see bmpcollector.Record.HandshakeComplete). Per RFC 7854
// §4.1, a well-behaved peer's very first message is always Initiation,
// so in practice this bucket is everything that ISN'T a well-behaved BMP
// peer: port scans, other TCP clients that happen to hit this port,
// stray/garbled bytes, etc. Without this bucket, the router_addr metric
// series store would grow one series per distinct source address that
// merely completes a TCP connection and manages to get any message
// (even a malformed one that partially decodes) through, which is
// unbounded and outside this collector's control. See README.md "Open
// questions".
const unidentifiedRouterAddr = "unidentified"

func (in *instruments) onRecord(logger *slog.Logger) bmpcollector.Callback {
	return func(rec bmpcollector.Record) {
		routerAddr := unidentifiedRouterAddr
		if rec.HandshakeComplete {
			routerAddr = addrHost(rec.RouterAddr)
		}
		msgType := messageTypeLabel(rec.Message.Header.Type)

		in.messagesTotal.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("message_type", msgType),
			attribute.String("router_addr", routerAddr),
		))

		logger.Debug("bmp-collector: decoded message",
			"router_addr", addrHost(rec.RouterAddr),
			"handshake_complete", rec.HandshakeComplete,
			"message_type", msgType,
			"peer_addr", rec.PeerHeader.PeerAddress.String(),
			"peer_as", rec.PeerHeader.PeerAS,
		)
	}
}

func (in *instruments) onError(logger *slog.Logger) bmpcollector.ErrorCallback {
	return func(routerAddr net.Addr, handshakeComplete bool, err error) {
		// Cardinality-bug fix: this must gate on handshakeComplete the
		// exact same way onRecord already gates router_addr, via the
		// same unidentifiedRouterAddr bucket. Before this fix, onError
		// had no handshake signal at all and always used the real
		// address as the router_addr label -- so, unlike onRecord, a
		// port scan or any other stray TCP client that never completes
		// a BMP handshake but manages to trip a decode/read error (the
		// easiest possible bar: any non-BMP bytes at all) minted its
		// own bmp.decode_errors_total series forever, unbounded by
		// anything this collector controls.
		routerAddrLabel := unidentifiedRouterAddr
		if handshakeComplete {
			routerAddrLabel = addrHost(routerAddr)
		}
		in.decodeErrorTotal.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("router_addr", routerAddrLabel),
		))
		logger.Warn("bmp-collector: connection error",
			"router_addr", addrHost(routerAddr), "handshake_complete", handshakeComplete, "err", err)
	}
}

func addrHost(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
