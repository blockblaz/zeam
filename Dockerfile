# Build stage
FROM ubuntu:24.04 AS builder

# Use bash and enable pipefail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.14.0
RUN curl -L https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz | tar -xJ \
    && mv zig-linux-x86_64-0.14.0 /opt/zig \
    && ln -s /opt/zig/zig /usr/local/bin/zig

# Install Rust 1.85+
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0
ENV PATH="/root/.cargo/bin:${PATH}"

# Install RISC0 toolchain using rzup (only for linux/amd64)
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        curl -L https://risczero.com/install | bash && \
        export PATH="/root/.risc0/bin:${PATH}" && \
        rzup install; \
    fi
ENV PATH="/root/.risc0/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY build.zig.zon ./
COPY build.zig ./

# Copy source code
COPY pkgs/ ./pkgs/
COPY build/ ./build/
COPY resources/ ./resources/
COPY rust/ ./rust/
COPY LICENSE ./
COPY README.md ./

# Copy git directory to get commit hash (exclude large objects)
COPY .git/HEAD .git/HEAD
COPY .git/refs .git/refs

# Get git commit hash and build the project with optimizations
RUN GIT_VERSION=$(cat .git/HEAD | grep -o '[0-9a-f]\{40\}' || echo "unknown") && \
    if [ -z "$GIT_VERSION" ] || [ "$GIT_VERSION" = "unknown" ]; then \
        REF=$(cat .git/HEAD | sed 's/ref: //'); \
        GIT_VERSION=$(cat ".git/$REF" 2>/dev/null | head -c 7 || echo "unknown"); \
    else \
        GIT_VERSION=$(echo "$GIT_VERSION" | head -c 7); \
    fi && \
    zig build -Doptimize=ReleaseFast -Dgit_version="$GIT_VERSION"

# Runtime stage - using scratch for absolute minimal size
FROM scratch AS runtime

# Copy only the essential runtime libraries from Ubuntu
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/librt.so.1 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libstdc++.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib64/ld-linux-x86-64.so.2 /lib64/

# Copy SSL certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy built binaries
COPY --from=builder /app/zig-out/ /app/zig-out/

# Copy runtime resources
COPY --from=builder /app/resources/ /app/resources/

# Set the zeam binary as the entrypoint with beam parameter by default
ENTRYPOINT ["/app/zig-out/bin/zeam", "beam"]

# IMPORTANT NOTES:
#
#
# 1. The 'clock' and 'beam' commands use xev event loop which may have 
#    container compatibility issues. The PermissionDenied error occurs even
#    with additional capabilities. This appears to be a limitation of running
#    the xev-based event loop in a containerized environment.
#
# 2. The scratch image has no users, shells, or package managers - only
#    the binary and required libraries.
#
# 3. For debugging, you'll need to copy the binary to another container
#    with debugging tools.
#
# 4. The final image uses scratch base with manually copied libraries
#    for the absolute minimal size possible.
