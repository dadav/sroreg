# Build stage
FROM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o sroreg main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS/TLS
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/sroreg .

# Copy templates and static files
COPY templates/ ./templates/
COPY static/ ./static/

# Create non-root user
RUN addgroup -g 1000 sroreg && \
    adduser -D -u 1000 -G sroreg sroreg && \
    chown -R sroreg:sroreg /app

USER sroreg

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/login || exit 1

# Run the application
ENTRYPOINT ["/app/sroreg"]
