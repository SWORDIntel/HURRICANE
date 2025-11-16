# HURRICANE v6-gatewayd Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM debian:12-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libc6-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /build
COPY . .

# Build the daemon
RUN make clean && make

# Runtime stage
FROM debian:12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    iproute2 \
    iputils-ping \
    curl \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/lib/v6-gatewayd /var/run /usr/local/share/v6-gatewayd/web

# Copy binaries from build stage
COPY --from=builder /build/v6-gatewayd /usr/local/bin/
COPY --from=builder /build/v6gw-keygen /usr/local/bin/

# Copy configuration and web files
COPY config/v6-gatewayd.conf.example /etc/v6-gatewayd.conf
COPY web/index.html /usr/local/share/v6-gatewayd/web/

# Create non-root user for runtime (note: needs NET_ADMIN capability)
RUN useradd -r -s /bin/false v6gatewayd

# Expose API port
EXPOSE 8642

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8642/health || exit 1

# Set working directory
WORKDIR /var/lib/v6-gatewayd

# Run as root (required for tunnel operations)
# In production, use --cap-add=NET_ADMIN instead
USER root

# Start the daemon
CMD ["/usr/local/bin/v6-gatewayd", "-c", "/etc/v6-gatewayd.conf"]
