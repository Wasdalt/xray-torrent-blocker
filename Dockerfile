# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download && CGO_ENABLED=0 GOOS=linux go build -o tblocker .

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache iptables conntrack-tools

WORKDIR /app
COPY --from=builder /app/tblocker /app/

# Конфиг по умолчанию
ENV TBLOCKER_LOG_FILE="/var/log/xray/access.log"
ENV TBLOCKER_STORAGE_DIR="/app/data"

ENTRYPOINT ["/app/tblocker", "-c", "/app/config.yaml"]
