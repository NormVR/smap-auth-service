FROM golang:1.25-alpine AS builder
WORKDIR /app

RUN apk add --no-cache \
    ca-certificates \
    build-base \
    musl-dev \
    pkgconfig

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=1 \
    CC=gcc \
    GOOS=linux \
    GOARCH=amd64 \
    go build -ldflags="-linkmode external -extldflags '-static' -w -s" \
    -tags musl \
    -trimpath \
    -o auth-service cmd/grpc/main.go

FROM alpine:3.20
WORKDIR /app/

RUN apk add --no-cache \
    ca-certificates \
    tzdata

COPY --from=builder /app/auth-service .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD grpc_health_probe -addr=:50051 -tls=false || exit 1

EXPOSE 50051
CMD ["./auth-service"]