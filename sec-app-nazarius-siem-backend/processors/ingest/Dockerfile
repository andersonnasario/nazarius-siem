# Build ingest processor (Go)
FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY . .
# For processors/ingest we use its own module; switch to its dir and run module commands there
WORKDIR /src/processors/ingest
RUN apk add --no-cache git build-base \
    && go env -w GO111MODULE=on \
    && go get ./... \
    && go mod download \
    && CGO_ENABLED=0 GOOS=linux go build -o /out/siem-ingest

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/siem-ingest /usr/local/bin/siem-ingest
ENTRYPOINT ["/usr/local/bin/siem-ingest"]
