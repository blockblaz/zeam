# Zeam API Package

## Overview

This package provides the HTTP API facilities for serving metrics and events from the `zeam` node:

- Server-Sent Events (SSE) stream for real-time chain events at `/events`
- Prometheus metrics endpoint at `/metrics`
- Health check at `/health`

The primary components are:
- Core API surface in `src/lib.zig` (`@zeam/api`) - re-exports metrics and serves HTTP endpoints
- Event system: `src/events.zig` and `src/event_broadcaster.zig`
- Metrics definitions in `pkgs/metrics/src/lib.zig` (`@zeam/metrics`) - separate package
- The underlying Prometheus client library: [karlseguin/metrics.zig](https://github.com/karlseguin/metrics.zig)
- A dedicated HTTP API server in `pkgs/cli/src/api_server.zig` (serves SSE, metrics, health)

## Metrics Exposed

The following metrics are defined in `pkgs/metrics/src/lib.zig` and served via the `/metrics` endpoint:

- **`chain_onblock_duration_seconds`** (Histogram)
  - **Description**: Measures the time taken to process a block within the `chain.onBlock` function (end-to-end block processing).
  - **Labels**: None.

- **`block_processing_duration_seconds`** (Histogram)
  - **Description**: Measures the time taken to process a block in the state transition function.
  - **Labels**: None.

- **`lean_head_slot`** (Gauge)
  - **Description**: Latest slot of the lean chain (canonical chain head as determined by fork choice).
  - **Labels**: None.
  - **Sample Collection Event**: Updated on every fork choice head update.

- **`lean_latest_justified_slot`** (Gauge)
  - **Description**: Latest justified slot.
  - **Labels**: None.
  - **Sample Collection Event**: Updated on state transition completion.

- **`lean_latest_finalized_slot`** (Gauge)
  - **Description**: Latest finalized slot.
  - **Labels**: None.
  - **Sample Collection Event**: Updated on state transition completion.

- **`lean_state_transition_time_seconds`** (Histogram)
  - **Description**: Time to process state transition.
  - **Labels**: None.
  - **Buckets**: 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4
  - **Sample Collection Event**: On state transition.

- **`lean_state_transition_slots_processed_total`** (Counter)
  - **Description**: Total number of processed slots (including empty slots).
  - **Labels**: None.
  - **Sample Collection Event**: On state transition process slots.

- **`lean_state_transition_slots_processing_time_seconds`** (Histogram)
  - **Description**: Time taken to process slots.
  - **Labels**: None.
  - **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
  - **Sample Collection Event**: On state transition process slots.

- **`lean_state_transition_block_processing_time_seconds`** (Histogram)
  - **Description**: Time taken to process block.
  - **Labels**: None.
  - **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
  - **Sample Collection Event**: On state transition process block.

- **`lean_state_transition_attestations_processed_total`** (Counter)
  - **Description**: Total number of processed attestations.
  - **Labels**: None.
  - **Sample Collection Event**: On state transition process attestations.

- **`lean_state_transition_attestations_processing_time_seconds`** (Histogram)
  - **Description**: Time taken to process attestations.
  - **Labels**: None.
  - **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
  - **Sample Collection Event**: On state transition process attestations.

## How It Works

The API system is initialized at application startup in `pkgs/cli/src/main.zig`. 

1.  `api.init()` is called once to set up histograms used by the node.
2.  A dedicated HTTP API server is started via `startAPIServer()` to serve SSE, metrics, and health.
3.  This server runs in a background thread and exposes:
    - SSE at `/events`
    - Metrics at `/metrics`
    - Health at `/health`

**Note**: For freestanding targets (zkvm runs), the API metrics operate in no-op mode and the HTTP server is disabled.

## Architecture

The metrics and API system follows a layered architecture with clear separation of concerns:

### Layer 1: Metrics Package (`pkgs/metrics`)
The `@zeam/metrics` package provides the core metrics infrastructure:
- Defines all application metrics (Histograms, Gauges, Counters)
- Provides the Timer API for time-based measurements
- Handles ZKVM/freestanding target detection and automatic no-op behavior
- Uses compile-time checks to avoid compiling unsupported code for freestanding targets
- Wraps the external [karlseguin/metrics.zig](https://github.com/karlseguin/metrics.zig) library

**Key feature:** Packages like `@zeam/state-transition` and `@zeam/node` can import `@zeam/metrics` directly without depending on HTTP/API infrastructure.

### Layer 2: API Package (`pkgs/api`)
This package (current):
- Re-exports metrics from `@zeam/metrics` for convenience
- Provides HTTP serving functionality for metrics via `/metrics` endpoint
- Implements SSE event broadcasting via `/events`
- Provides health checks via `/health`

### Layer 3: HTTP Server (`pkgs/cli/src/api_server.zig`)
The dedicated HTTP server implementation:
- Runs independently in a background thread
- Serves SSE at `/events`
- Serves Prometheus-formatted metrics at `/metrics`
- Provides health checks at `/health`
- Automatically disabled for ZKVM targets (no HTTP server for freestanding environments)

### Dependency Flow
```
pkgs/metrics/         ← Core metrics definitions
    ↓
    ├─→ pkgs/api/           ← Re-exports metrics, HTTP serving
    ├─→ pkgs/state-transition/  ← Uses metrics directly
    └─→ pkgs/node/              ← Uses metrics directly
```

## Freestanding Target Support

The metrics library automatically detects freestanding targets (like zkvm runs) and operates in no-op mode:

- **Host targets**: Full metrics functionality with HTTP server
- **Freestanding targets**: No-op metrics using compile-time checks to avoid compiling system calls like `std.time.nanoTimestamp()`

This ensures compatibility with zero-knowledge proof environments where traditional system calls, networking, and threading are not available.

## Running for Visualization

The dashboards and monitoring infrastructure have been moved to a separate repository: [zeam-dashboards](https://github.com/blockblaz/zeam-dashboards).

### Quick Setup

1. **Clone the dashboard repository**:
```sh
git clone https://github.com/blockblaz/zeam-dashboards.git
cd zeam-dashboards
```

2. **Generate Prometheus configuration**:
```sh
# From your Zeam repository
./zig-out/bin/zeam prometheus genconfig -f prometheus/prometheus.yml
```

3. **Start the monitoring stack**:
```sh
docker-compose up -d
```

4. **Access dashboards**:
- Grafana: http://localhost:3001 (admin/admin)
- Prometheus: http://localhost:9090

For detailed setup instructions and troubleshooting, see the [zeam-dashboards repository](https://github.com/blockblaz/zeam-dashboards).

**Important**: Make sure the metrics port in your `prometheus.yml` file matches the port used when starting the beam command.

### Verify and Visualize

1.  **Check Prometheus Targets**: Open the Prometheus UI at [http://localhost:9090/targets](http://localhost:9090/targets). The `zeam_app` job should be **UP**.
2.  **Build a Grafana Dashboard**: Create a new dashboard and panel. Use a query like the following to visualize the 95th percentile of block processing time:
```promql
histogram_quantile(0.95, sum(rate(chain_onblock_duration_seconds_bucket[5m])) by (le))
```

## CLI Commands

The `zeam` executable provides several commands for working with metrics:

### Beam Command
Run a full Beam node with configurable metrics:

```sh
# Use default metrics port (9667)
./zig-out/bin/zeam beam

# Use custom metrics port
./zig-out/bin/zeam beam --metricsPort 8080

# Use mock network for testing
./zig-out/bin/zeam beam --mockNetwork --metricsPort 8080
```

### Generate Prometheus Config
Generate a Prometheus configuration file that matches your metrics settings:

```sh
# Generate config with default port (9667)
./zig-out/bin/zeam prometheus genconfig -f prometheus/prometheus.yml

# Generate config with custom port
./zig-out/bin/zeam prometheus genconfig --metricsPort 8080 -f prometheus.yml
```

## Testing the API Server

You can test that the API server is working by:

1. **Starting the beam node**:
```sh
./zig-out/bin/zeam beam --mockNetwork --metricsPort 9668
```

2. **Checking the SSE endpoint**:
```sh
curl -N http://localhost:9668/events
```

3. **Checking the metrics endpoint**:
```sh
curl http://localhost:9668/metrics
```

4. **Checking the health endpoint**:
```sh
curl http://localhost:9668/health
```

## Adding New Metrics

To add a new metric, follow these steps:

### 1. Define the Metric Type
In `pkgs/metrics/src/lib.zig`, add your metric to the `Metrics` struct:

```zig
const Metrics = struct {
    // ... existing metrics ...
    my_new_metric: MyNewMetricHistogram,
    
    const MyNewMetricHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.05, 0.1, 0.5, 1.0 });
};
```

### 2. Initialize the Metric
In the `init()` function in `pkgs/metrics/src/lib.zig`:

```zig
pub fn init(allocator: std.mem.Allocator) !void {
    // ... existing initialization ...
    metrics = .{
        // ... existing metrics ...
        .my_new_metric = Metrics.MyNewMetricHistogram.init(
            "my_new_metric",
            .{ .help = "Description of what this metric measures." },
            .{}
        ),
    };
}
```

### 3. Create Wrapper (for Histograms with Timer API)
If it's a timing metric, create a wrapper variable and observer function:

```zig
fn observeMyNewMetric(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.MyNewMetricHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

pub var my_new_metric: Histogram = .{
    .context = null,
    .observe = &observeMyNewMetric,
};
```

And initialize the context in `init()`:
```zig
my_new_metric.context = @ptrCast(&metrics.my_new_metric);
```

### 4. Use the Metric
Import the metrics package and use the Timer API for timing metrics:

```zig
const zeam_metrics = @import("@zeam/metrics");

// For timing measurements - use Timer API (recommended)
const timer = zeam_metrics.my_new_metric.start();
// ... do work ...
_ = timer.observe();

// For direct observations (Gauges, Counters)
zeam_metrics.metrics.my_gauge.set(42);
zeam_metrics.metrics.my_counter.incrBy(1);
```

**Important:** Always use the Timer API for timing measurements instead of manual timestamp calculations. The Timer API automatically handles ZKVM targets and uses compile-time checks to avoid compilation errors on freestanding platforms.
