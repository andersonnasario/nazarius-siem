# Build the Go API
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git build-base

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies and tidy
RUN export GOTOOLCHAIN=auto && go mod download && go mod tidy

# Copy source code
COPY rest ./rest/
COPY database ./database/

# Build the API (use -mod=mod to allow go.sum updates)
RUN export GOTOOLCHAIN=auto && \
    CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-w -s" -o /out/siem-api ./rest/*.go

# Small runtime image
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 siem && \
    adduser -D -u 1000 -G siem siem

# Copy binary
COPY --from=builder /out/siem-api /usr/local/bin/siem-api

# Set ownership
RUN chown siem:siem /usr/local/bin/siem-api

# Switch to non-root user
USER siem

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Start the API
ENTRYPOINT ["/usr/local/bin/siem-api"]
