# Multi-stage build producing two images from one file. Pick which with
# `--target server` or `--target worker`; docker-compose does this for you.

FROM golang:1.26-alpine AS build
WORKDIR /src

# Dependencies are copied first so that a code-only change does not invalidate
# the module download layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

# --- API server -------------------------------------------------------------
# The server never shells out, so it needs nothing but CA certificates.
FROM alpine:3.21 AS server
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 sbomdelta
COPY --from=build /out/server /usr/local/bin/server
USER sbomdelta
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]

# --- Scan worker ------------------------------------------------------------
# The worker shells out to git and syft, so both have to be on its PATH.
FROM alpine:3.21 AS worker
RUN apk add --no-cache ca-certificates git && adduser -D -u 10001 sbomdelta
COPY --from=anchore/syft:latest /syft /usr/local/bin/syft
COPY --from=build /out/worker /usr/local/bin/worker

# Clone directories live here; mount a volume over it to keep large checkouts
# off the container filesystem.
RUN mkdir -p /var/lib/sbomdelta && chown sbomdelta:sbomdelta /var/lib/sbomdelta
ENV SCANNER_WORK_DIR=/var/lib/sbomdelta
USER sbomdelta
ENTRYPOINT ["/usr/local/bin/worker"]