# Zeam Metrics Package

## Overview

This package provides Prometheus metrics for the `zeam` application. It allows for instrumentation of the code to expose key performance indicators and health statistics.

The primary components are:
- A metrics service implemented in `src/lib.zig`.
- The underlying Prometheus client library: [karlseguin/metrics.zig](https://github.com/karlseguin/metrics.zig).
- A dedicated HTTP metrics server in `pkgs/cli/src/metrics_server.zig`.

## Metrics Exposed

The following metrics are currently available:

- **`chain_onblock_duration_seconds`** (Histogram)
  - **Description**: Measures the time taken to process a block within the `chain.onBlock` function (end-to-end block processing).
  - **Labels**: None.

- **`block_processing_duration_seconds`** (Histogram)
  - **Description**: Measures the time taken to process a block in the state transition function.
  - **Labels**: None.

## How It Works

The metrics system is initialized at application startup in `pkgs/cli/src/main.zig`. 

1.  `metrics.init()` is called once to set up the metric registry and define all histograms, counters, and gauges.
2.  A dedicated HTTP metrics server is started via `metricsServer.startMetricsServer()` to serve metrics on the specified port.
3.  This server runs in a background thread and exposes metrics at the `/metrics` endpoint and health at `/health` endpoint, making them available for a Prometheus server to scrape.

**Note**: For freestanding targets (zkvm runs), the metrics system operates in no-op mode and does not start an HTTP server.

## Architecture

The metrics system uses a dedicated HTTP server implementation (`pkgs/cli/src/metrics_server.zig`) that:

- Runs independently of the main application
- Serves Prometheus-formatted metrics at `/metrics`
- Provides health checks at `/health`
- Automatically handles ZKVM targets (no HTTP server for freestanding environments)
- Uses background threading to avoid blocking the main application

## Freestanding Target Support

The metrics library automatically detects freestanding targets (like zkvm runs) and operates in no-op mode:

- **Host targets**: Full metrics functionality with HTTP server
- **Freestanding targets**: No-op metrics that don't use system calls like `std.net` or `std.Thread`

This ensures compatibility with zero-knowledge proof environments where traditional networking and threading are not available.

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

## Testing the Metrics Server

You can test that the metrics server is working by:

1. **Starting the beam node**:
   ```sh
   ./zig-out/bin/zeam beam --mockNetwork --metricsPort 9668
   ```

2. **Checking the metrics endpoint**:
   ```sh
   curl http://localhost:9668/metrics
   ```

3. **Checking the health endpoint**:
   ```sh
   curl http://localhost:9668/health
   ```

## Adding New Metrics

To add a new metric, follow the existing pattern:

1.  **Declare it**: Add a new global variable for your metric in `pkgs/metrics/src/lib.zig`.
2.  **Initialize it**: In the `init()` function in `lib.zig`, initialize the metric with its name, help text, and any labels or buckets.
3.  **Use it**: Import the metrics package in your application code and record observations (e.g., `metrics.my_new_metric.observe(value)`).
