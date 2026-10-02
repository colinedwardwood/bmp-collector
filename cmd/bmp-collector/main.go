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
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := run(*listenAddr, *metricsAddr, *otlpEndpoint, *otlpInsecure, *pushInterval, logger); err != nil {
		logger.Error("bmp-collector: exiting", "err", err)
		os.Exit(1)
	}
}

func run(listenAddr, metricsAddr, otlpEndpoint string, otlpInsecure bool, pushInterval time.Duration, logger *slog.Logger) error {
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
	if otlpEndpoint != "" {
		opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(otlpEndpoint)}
		if otlpInsecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		otlpExp, err = otlpmetrichttp.New(ctx, opts...)
		if err != nil {
			return fmt.Errorf("build OTLP metric exporter: %w", err)
		}
		readers = append(readers, sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(otlpExp, sdkmetric.WithInterval(pushInterval)),
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

	col := bmpcollector.New(listenAddr, inst.onRecord(logger),
		bmpcollector.WithErrorCallback(inst.onError(logger)),
		bmpcollector.WithLogger(logger),
	)
	if err := col.Start(ctx); err != nil {
		return fmt.Errorf("start collector: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	metricsSrv := &http.Server{Addr: metricsAddr, Handler: mux}
	go func() {
		logger.Info("bmp-collector: serving /metrics", "addr", metricsAddr)
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
	return func(routerAddr net.Addr, err error) {
		in.decodeErrorTotal.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("router_addr", addrHost(routerAddr)),
		))
		logger.Warn("bmp-collector: connection error", "router_addr", addrHost(routerAddr), "err", err)
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
