# Zeam Metrics Package

## Overview

This package provides Prometheus metrics for the `zeam` application. It allows for instrumentation of the code to expose key performance indicators and health statistics.

The primary components are:
- A metrics service implemented in `src/lib.zig`.
- The underlying Prometheus client library: [karlseguin/metrics.zig](https://github.com/karlseguin/metrics.zig).

## Metrics Exposed

The following metrics are currently available:

- **`chain_onblock_duration_seconds`** (Histogram)
  - **Description**: Measures the time taken to process a block within the `chain.onBlock` function (end-to-end block processing).
  - **Labels**: None.

**Note**: The `block_processing_duration_seconds` metric has been removed to simplify the metrics architecture. Block processing is now measured end-to-end at the chain level only.

## How It Works

The metrics system is initialized at application startup in `pkgs/cli/src/main.zig`. 

1.  `metrics.init()` is called once to set up the metric registry and define all histograms, counters, and gauges.
2.  `metrics.startListener()` is called to spawn a background thread that runs an HTTP server.
3.  This server listens on a configurable port (default: `9667`) and exposes all registered metrics at the `/metrics` endpoint, making them available for a Prometheus server to scrape.

**Note**: For freestanding targets (zkvm runs), the metrics system operates in no-op mode and does not start an HTTP server.

## Freestanding Target Support

The metrics library automatically detects freestanding targets (like zkvm runs) and operates in no-op mode:

- **Host targets**: Full metrics functionality with HTTP server
- **Freestanding targets**: No-op metrics that don't use system calls like `std.net` or `std.Thread`

This ensures compatibility with zero-knowledge proof environments where traditional networking and threading are not available.

## Running for Visualization (Local Setup)

Here is a complete guide to running the `zeam` node and visualizing its metrics in Grafana.

### Prerequisites

You must have Docker installed.

### 1. Build the Application

From the root of the `zeam` repository, compile the application:

```sh
zig build
```

### 2. Configure and Run Prometheus

Generate a Prometheus configuration file that matches your metrics port:

```sh
# Generate config with default port (9667)
./zig-out/bin/zeam generate_prometheus_config

# Or generate config with custom port
./zig-out/bin/zeam generate_prometheus_config --metricsPort 8080
```

By default, this creates a `prometheus.yml` file in your current directory. When run from the root of the `zeam` repository, it automatically places the file in `pkgs/metrics/prometheus/` to support the local Docker Compose setup. 

Run Prometheus and Grafana using Docker Compose from the metrics folder:

```sh
cd pkgs/metrics
docker-compose up -d
```

### 3. Configure and Run Grafana

Run the Grafana Docker container, also on the host network:

```sh
docker run -d --name grafana --network="host" grafana/grafana
```

- Access Grafana at [http://localhost:3000](http://localhost:3000) (default login: `admin`/`admin`).
- Add Prometheus as a data source:
  - **URL**: `http://localhost:9090`
  - Click "Save & Test".

### 4. Run the Zeam Application

Start the `zeam` node in the background. We recommend redirecting its output to a log file.

```sh
# Use default metrics port (9667)
./zig-out/bin/zeam beam > zeam.log 2>&1 &

# Or use custom metrics port
./zig-out/bin/zeam beam --metricsPort 8080 > zeam.log 2>&1 &
```

**Important**: Make sure the metrics port in your `prometheus.yml` file matches the port used when starting the beam command.

### 5. Verify and Visualize

1.  **Check Prometheus Targets**: Open the Prometheus UI at [http://localhost:9090/targets](http://localhost:9090/targets). Both the `zeam` and `zeam_app` jobs should be **UP**.
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
./zig-out/bin/zeam generate_prometheus_config

# Generate config with custom port
./zig-out/bin/zeam generate_prometheus_config --metricsPort 8080

# Output to stdout
./zig-out/bin/zeam generate_prometheus_config --metricsPort 8080 --output -

# Output to custom file
./zig-out/bin/zeam generate_prometheus_config --metricsPort 8080 --output custom_prometheus.yml
```

## Adding New Metrics

To add a new metric, follow the existing pattern:

1.  **Declare it**: Add a new global variable for your metric in `pkgs/metrics/src/lib.zig`.
2.  **Initialize it**: In the `init()` function in `lib.zig`, initialize the metric with its name, help text, and any labels or buckets.
3.  **Use it**: Import the metrics package in your application code and record observations (e.g., `metrics.my_new_metric.observe(value)`).
