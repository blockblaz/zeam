# Build stage
FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    xz-utils \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.14.0
RUN curl -L https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz | tar -xJ \
    && mv zig-linux-x86_64-0.14.0 /opt/zig \
    && ln -s /opt/zig/zig /usr/local/bin/zig

# Install Rust 1.85+
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0
ENV PATH="/root/.cargo/bin:${PATH}"

# Install RISC0 toolchain
RUN cargo install cargo-risczero && \
    cargo risczero install

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY build.zig.zon ./
COPY build.zig ./

# Copy source code
COPY pkgs/ ./pkgs/
COPY resources/ ./resources/
COPY LICENSE ./
COPY README.md ./

# Build the project with optimizations
RUN zig build -Doptimize=ReleaseFast

# Runtime stage
FROM ubuntu:24.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (use UID 1001 to avoid conflicts with default Ubuntu user)
RUN useradd -m -u 1001 -s /bin/bash zeam

# Copy built binaries from builder
COPY --from=builder /app/zig-out/bin/ /usr/local/bin/

# Copy any runtime configuration or data
COPY --from=builder /app/resources/ /app/resources/

# Switch to non-root user
USER zeam
WORKDIR /app

# Default command - can be overridden
ENTRYPOINT ["/usr/local/bin/zeam"]
CMD ["clock"]