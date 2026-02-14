# Build ingest processor (Go)
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY . .
# For processors/ingest we use its own module; switch to its dir and run module commands there
WORKDIR /src/processors/ingest
RUN apk add --no-cache git build-base \
    && go env -w GO111MODULE=on \
    && go get ./... \
    && go mod download \
    && CGO_ENABLED=0 GOOS=linux go build -o /out/siem-ingest

# Small runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 siem && \
    adduser -D -u 1000 -G siem siem

COPY --from=builder /out/siem-ingest /usr/local/bin/siem-ingest
RUN chown siem:siem /usr/local/bin/siem-ingest

# Switch to non-root user
USER siem

ENTRYPOINT ["/usr/local/bin/siem-ingest"]
