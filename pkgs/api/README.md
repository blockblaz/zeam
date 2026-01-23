# Zeam API Package

## Overview

This package provides the HTTP API server for the Zeam node with five main endpoints:

- Server-Sent Events (SSE) stream for real-time chain events at `/events`
- Prometheus metrics endpoint at `/metrics`
- Health check at `/lean/v0/health`
- Finalized checkpoint state at `/lean/v0/states/finalized` (for checkpoint sync)
- Justified checkpoint information at `/lean/v0/states/justified`

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

### 2. Health Checks

Simple health check endpoint at `/lean/v0/health`.

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

### `/lean/v0/health`

Returns node health status.

```sh
curl http://localhost:9667/lean/v0/health
```

### `/lean/v0/states/finalized`

Returns the finalized checkpoint state as SSZ-encoded binary for checkpoint sync.

```sh
curl http://localhost:9667/lean/v0/states/finalized -o finalized_state.ssz
```

Returns:
- **Content-Type**: `application/octet-stream`
- **Body**: SSZ-encoded `BeamState`
- **Status 503**: Returned if no finalized state is available yet

### `/lean/v0/states/justified`

Returns the latest justified checkpoint information as JSON.

```sh
curl http://localhost:9667/lean/v0/states/justified
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

// Start HTTP server in background thread
try api_server.startAPIServer(allocator, apiPort);
```

The server exposes:
- SSE at `/events`
- Metrics at `/metrics`
- Health at `/lean/v0/health`
- Checkpoint state at `/lean/v0/states/finalized`
- Justified checkpoint at `/lean/v0/states/justified`

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
./zig-out/bin/zeam beam --mockNetwork --api-port 9668
```

Test endpoints:

```sh
# SSE events
curl -N http://localhost:9668/events

# Metrics
curl http://localhost:9668/metrics

# Health
curl http://localhost:9668/lean/v0/health

# Checkpoint state
curl http://localhost:9668/lean/v0/states/finalized -o state.ssz

# Justified checkpoint
curl http://localhost:9668/lean/v0/states/justified
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
