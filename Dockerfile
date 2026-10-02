# syntax=docker/dockerfile:1

# --- builder -----------------------------------------------------------
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 for a fully static binary that runs on a scratch/
# distroless base with no libc. Version/commit could be injected here via
# -ldflags if/when this repo starts tagging builds with build metadata.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/bmp-collector ./cmd/bmp-collector

# --- runtime -------------------------------------------------------------
# distroless/static: no shell, no package manager, just a minimal libc-free
# root filesystem plus CA certs -- appropriate for a static Go binary that
# (per -otlp-endpoint) may dial out over TLS to push metrics.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/bmp-collector /usr/local/bin/bmp-collector

# BMP TCP listener (routers dial in here) and the Prometheus /metrics
# endpoint; see cmd/bmp-collector's -listen/-metrics-addr flags.
EXPOSE 1790 9464

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/bmp-collector"]
