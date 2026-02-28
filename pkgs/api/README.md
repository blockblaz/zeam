# Zeam API Package

## Overview

This package provides two HTTP servers for the Zeam node:

**Metrics Server** (port 9668) - starts immediately:
- `/metrics` - Prometheus metrics
- `/lean/v0/health` - Liveness check

**API Server** (port 9667) - starts after chain init:
- `/lean/v0/ready` - Readiness check
- `/lean/v0/states/finalized` - Checkpoint state (for checkpoint sync)
- `/lean/v0/checkpoints/justified` - Justified checkpoint info
- `/api/forkchoice/graph` - Fork choice visualization (Grafana compatible)
- `/events` - SSE stream for real-time chain events

## Package Components

- `src/lib.zig` - Core API module with initialization and metrics serialization
- `src/events.zig` - Event type definitions (NewHeadEvent, NewJustificationEvent, NewFinalizationEvent)
- `src/event_broadcaster.zig` - SSE broadcaster for real-time events
- `src/routes.zig` - HTTP route handlers
- `pkgs/cli/src/api_server.zig` - HTTP server implementation (runs in background thread)

## Metrics Exposed

This package **serves** metrics via the `/metrics` HTTP endpoint in Prometheus format. Metrics are **defined** in `@zeam/metrics`.

**For all metrics documentation (definitions, usage, adding new metrics), see:** [`pkgs/metrics/README.md`](../metrics/README.md)

### 1. Broadcasts Events via SSE

Provides real-time chain event streaming via Server-Sent Events:
- `new_head` - Fork choice selects new head
- `new_justification` - New justified checkpoint
- `new_finalization` - New finalized checkpoint

### 2. Health & Readiness Checks

- `/lean/v0/health` on metrics server (9668) - Liveness check, available immediately
- `/lean/v0/ready` on API server (9667) - Readiness check, available after chain init

## Event System

Events are defined in `src/events.zig`:

```zig
pub const ChainEvent = union(enum) {
    new_head: NewHeadEvent,
    new_justification: NewJustificationEvent,
    new_finalization: NewFinalizationEvent,
};
```

### Broadcasting Events in Code

```zig
const api = @import("@zeam/api");

// Create and broadcast an event
if (api.events.NewHeadEvent.fromProtoBlock(allocator, new_head)) |head_event| {
    var chain_event = api.events.ChainEvent{ .new_head = head_event };
    api.event_broadcaster.broadcastGlobalEvent(&chain_event) catch |err| {
        // Handle error
    };
}
```

### Consuming Events

Connect to the SSE endpoint:

```sh
curl -N http://localhost:9667/events
```

Events are streamed in SSE format:

```
event: head
data: {"slot":12345,"block_root":"0x...","state_root":"0x..."}

event: justification
data: {"epoch":123,"root":"0x...","current_slot":12345}
```

## HTTP Endpoints

### `/metrics`

Returns Prometheus-formatted metrics. Metrics are collected from `@zeam/metrics` and serialized by this package.

```sh
curl http://localhost:9667/metrics
```

**For what metrics are available, see:** [`pkgs/metrics/README.md`](../metrics/README.md)

### `/events`

Streams real-time chain events (head, justification, finalization).

```sh
curl -N http://localhost:9667/events
```

### `/lean/v0/health` (Metrics Server)

Returns liveness status. Available immediately on metrics port.

```sh
curl http://localhost:9668/lean/v0/health
```

### `/lean/v0/ready` (API Server)

Returns readiness status. Available after chain initialization.

```sh
curl http://localhost:9667/lean/v0/ready
```

### `/api/forkchoice/graph`

Returns the fork choice tree as JSON compatible with Grafana's node-graph panel. Useful for visualizing chain forks, head selection, and finalization progress.

```sh
# Default (last 50 slots)
curl http://localhost:9667/api/forkchoice/graph

# Custom slot range (max 200)
curl http://localhost:9667/api/forkchoice/graph?slots=100
```

**Note:** Returns 503 Service Unavailable if chain is not yet initialized. The graph includes all nodes from the finalized checkpoint up to head; if `head_slot - finalized_slot < slots`, the response will contain fewer than the requested number of slots.


**Rate limiting:** 2 requests/second per IP with burst of 5. Max 2 concurrent graph generations.

### `/lean/v0/states/finalized`

Returns the finalized checkpoint state as SSZ-encoded binary for checkpoint sync.

```sh
curl http://localhost:9667/lean/v0/states/finalized -o finalized_state.ssz
```

Returns:
- **Content-Type**: `application/octet-stream`
- **Body**: SSZ-encoded `BeamState`
- **Status 503**: Returned if no finalized state is available yet

### `/lean/v0/checkpoints/justified`

Returns the latest justified checkpoint information as JSON.

```sh
curl http://localhost:9667/lean/v0/checkpoints/justified
```

Returns:
- **Content-Type**: `application/json`
- **Body**: JSON object with `slot` and `root` fields
- **Status 503**: Returned if chain is not initialized
- **Example response**: `{"root":"0x1234...","slot":42}`

## Usage

### Initialization

The API system is initialized at startup in `pkgs/cli/src/main.zig`:

```zig
// Initialize metrics
try api.init(allocator);

// Start metrics server early (no chain dependency)
var metrics_handle = try metrics_server.startMetricsServer(allocator, metrics_port, logger_config);

// After chain initialization, start API server
var api_handle = try api_server.startAPIServer(allocator, api_port, logger_config, chain);

// Graceful shutdown
api_handle.stop();
metrics_handle.stop();
```

**Metrics Server** (port 9668) - starts immediately:
- `/metrics` - Prometheus metrics
- `/lean/v0/health` - Liveness check (JSON)

**API Server** (port 9667) - starts after chain init:
- `/lean/v0/ready` - Readiness check (JSON)
- `/lean/v0/states/finalized` - Checkpoint state (SSZ)
- `/lean/v0/checkpoints/justified` - Justified checkpoint (JSON)
- `/api/forkchoice/graph` - Fork choice visualization (JSON)
- `/events` - SSE event streaming

**Note**: On freestanding targets (ZKVM), the HTTP server is automatically disabled.

### Dependency Flow

```
pkgs/metrics/              ← Defines and collects metrics
    ↓
pkgs/api/                  ← Serializes metrics, broadcasts events
    ↓
pkgs/cli/src/api_server.zig ← HTTP server (serves via endpoints)
```

## CLI Commands

### Running the Node

```sh
# Default API port (9667)
./zig-out/bin/zeam beam

# Custom port
./zig-out/bin/zeam beam --api-port 8080

# Mock network for testing
./zig-out/bin/zeam beam --mockNetwork --api-port 8080
```

### Generate Prometheus Config

```sh
# Default port (9667)
./zig-out/bin/zeam prometheus genconfig -f prometheus/prometheus.yml

# Custom port
./zig-out/bin/zeam prometheus genconfig --api-port 8080 -f prometheus.yml
```

## Testing

Start a node:

```sh
./zig-out/bin/zeam beam --mockNetwork
```

Test endpoints:

```sh
# Health (metrics server - port 9668)
curl http://localhost:9668/lean/v0/health

# Metrics (metrics server - port 9668)
curl http://localhost:9668/metrics

# Readiness (API server - port 9667)
curl http://localhost:9667/lean/v0/ready

# SSE events (API server - port 9667)
curl -N http://localhost:9667/events

# Checkpoint state (API server - port 9667)
curl http://localhost:9667/lean/v0/states/finalized -o state.ssz

# Justified checkpoint (API server - port 9667)
curl http://localhost:9667/lean/v0/checkpoints/justified
```

## Visualization with Prometheus & Grafana

Monitoring infrastructure: [zeam-dashboards](https://github.com/blockblaz/zeam-dashboards)

**Quick setup:**

```sh
# 1. Clone dashboards repo
git clone https://github.com/blockblaz/zeam-dashboards.git
cd zeam-dashboards

# 2. Generate Prometheus config
../zeam/zig-out/bin/zeam prometheus genconfig -f prometheus/prometheus.yml

# 3. Start stack
docker-compose up -d
```

**Access:**
- Grafana: http://localhost:3001 (admin/admin)
- Prometheus: http://localhost:9090

**Verify:** Check http://localhost:9090/targets - `zeam_app` should be **UP**.

**Example query** (95th percentile block processing):

```promql
histogram_quantile(0.95, sum(rate(chain_onblock_duration_seconds_bucket[5m])) by (le))
```

## Package Dependencies

**Depends on:**
- `@zeam/metrics` - Metrics definitions and serialization
- `@zeam/types` - Event type definitions
- `@zeam/utils` - Utility functions

**Used by:**
- `@zeam/node` - Event broadcasting
- `pkgs/cli` - HTTP API server
