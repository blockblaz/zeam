# Zeam Metrics Package

## Overview

The `@zeam/metrics` package provides the core metrics infrastructure for the Zeam node. It defines all application metrics (Histograms, Gauges, Counters) and provides a Timer API for time-based measurements.

Zeam follows the [Lean Ethereum metrics specification](https://github.com/leanEthereum/leanMetrics). All metrics prefixed with `lean_` are defined in that spec. Any Zeam-specific metrics that are not part of the spec use the `zeam_` prefix instead.

**Key Features:**
- Timer API for convenient time-based measurements
- Automatic ZKVM/freestanding target detection with no-op behavior
- Compile-time checks to avoid compiling unsupported code for freestanding targets
- Zero-overhead metrics collection when running in ZKVM environments

**Note:** This package is imported by `@zeam/state-transition`, `@zeam/node`, and other core packages. It does NOT depend on HTTP or API infrastructure, making it suitable for use in ZKVM environments.

## Architecture

### Design Principles

1. **Standalone Package**: No dependencies on HTTP, networking, or API infrastructure
2. **ZKVM Compatible**: Automatically becomes no-op on freestanding targets
3. **Compile-Time Safety**: Uses `comptime` checks to avoid compilation errors on platforms without system calls
4. **Zero Runtime Overhead**: When not initialized or on ZKVM targets, all operations are no-ops

### Platform Detection

The package automatically detects ZKVM environments:

```zig
pub fn isZKVM() bool {
    return @import("builtin").target.os.tag == .freestanding;
}
```

### Timer API

The Timer API provides a convenient way to measure time intervals without manually handling timestamps:

```zig
pub const Timer = struct {
    start_time: i128,
    context: ?*anyopaque,
    observe_impl: *const fn (?*anyopaque, f32) void,

    pub fn observe(self: Timer) f32 {
        // Calculates duration and records to histogram
        // Automatically handles ZKVM targets (returns 0.0)
    }
};
```

### No-Op Behavior

For freestanding targets (ZKVM):
- All metrics operations are no-ops
- No system calls are compiled
- Zero runtime overhead
- Metrics are initialized as no-op by default

## Metrics Definitions

All metrics are defined in the `Metrics` struct in `pkgs/metrics/src/lib.zig`. The following metrics are available:

### Chain Metrics

#### `zeam_chain_onblock_duration_seconds` (Histogram)
- **Description**: Measures the time taken to process a block within the `chain.onBlock` function (end-to-end block processing).
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
- **Labels**: None
- **Sample Collection Event**: On every block processed by the chain

### Event loop health (issues #863, #867)

These series help correlate **long `[clock]` `slot_interval` gaps** with wall time spent inside **`xev.Loop.run(.until_done)`** in `Clock.run` (completion backlog: gossip, reqresp, rust-bridge, etc.). They do **not** replace `zeam_chain_onblock_duration_seconds` for attributing slow **`onBlock`** — use both on the same timeline.

#### `zeam_xev_clock_until_done_drain_seconds` (Histogram)
- **Description**: Wall time for one `run(.until_done)` drain in the clock driver.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60
- **Labels**: None
- **Sample Collection Event**: After each clock-loop `run(.until_done)` completes

#### `zeam_xev_clock_until_done_slow_ge_500ms_total` (Counter)
- **Description**: Number of clock-loop drains taking ≥0.5s wall time.
- **Type**: Counter
- **Sample Collection Event**: When a drain completes at ≥0.5s

#### `zeam_xev_clock_until_done_slow_ge_1s_total` (Counter)
- **Description**: Number of clock-loop drains taking ≥1s wall time (same path also emits a `[clock]` **warn** log).
- **Type**: Counter
- **Sample Collection Event**: When a drain completes at ≥1s

### Fork Choice Metrics

#### `lean_head_slot` (Gauge)
- **Description**: Latest slot of the lean chain (canonical chain head as determined by fork choice).
- **Type**: Gauge
- **Unit**: Slot number (u64)
- **Labels**: None
- **Sample Collection Event**: Updated on every fork choice head update

#### `lean_latest_justified_slot` (Gauge)
- **Description**: Latest justified slot.
- **Type**: Gauge
- **Unit**: Slot number (u64)
- **Labels**: None
- **Sample Collection Event**: Updated on state transition completion

#### `lean_latest_finalized_slot` (Gauge)
- **Description**: Latest finalized slot.
- **Type**: Gauge
- **Unit**: Slot number (u64)
- **Labels**: None
- **Sample Collection Event**: Updated on state transition completion

#### `lean_fork_choice_block_processing_time_seconds` (Histogram)
- **Description**: Time taken to process block in fork choice.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
- **Labels**: None
- **Sample Collection Event**: On fork choice block processing

#### `lean_attestations_valid_total` (Counter)
- **Description**: Total number of valid attestations processed by fork choice.
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: source ("gossip", "aggregation", "block")
- **Sample Collection Event**: On successful attestation validation and processing

#### `lean_attestations_invalid_total` (Counter)
- **Description**: Total number of invalid attestations rejected by fork choice.
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: source ("gossip", "aggregation", "block")
- **Sample Collection Event**: On attestation validation failure

#### `lean_attestation_validation_time_seconds` (Histogram)
- **Description**: Time taken to validate attestations in fork choice.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
- **Labels**: None
- **Sample Collection Event**: On attestation validation and processing

### State Transition Metrics

#### `lean_state_transition_time_seconds` (Histogram)
- **Description**: Time to process state transition.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4
- **Labels**: None
- **Sample Collection Event**: On state transition

#### `lean_state_transition_slots_processed_total` (Counter)
- **Description**: Total number of processed slots (including empty slots).
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: None
- **Sample Collection Event**: On state transition process slots

#### `lean_state_transition_slots_processing_time_seconds` (Histogram)
- **Description**: Time taken to process slots.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
- **Labels**: None
- **Sample Collection Event**: On state transition process slots

#### `lean_state_transition_block_processing_time_seconds` (Histogram)
- **Description**: Time taken to process block.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
- **Labels**: None
- **Sample Collection Event**: On state transition process block

#### `lean_state_transition_attestations_processed_total` (Counter)
- **Description**: Total number of processed attestations.
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: None
- **Sample Collection Event**: On state transition process attestations

#### `lean_state_transition_attestations_processing_time_seconds` (Histogram)
- **Description**: Time taken to process attestations.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.005, 0.01, 0.025, 0.05, 0.1, 1
- **Labels**: None
- **Sample Collection Event**: On state transition process attestations

### Block Production Metrics

#### `lean_block_building_time_seconds` (Histogram)
- **Description**: Total time taken to build a block.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1
- **Labels**: None
- **Sample Collection Event**: On each block proposal attempt

#### `lean_block_building_payload_aggregation_time_seconds` (Histogram)
- **Description**: Time taken to aggregate attestation payloads during block building.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4
- **Labels**: None
- **Sample Collection Event**: On each block proposal attempt

#### `lean_block_aggregated_payloads` (Histogram)
- **Description**: Number of aggregated payloads included in a produced block.
- **Type**: Histogram
- **Unit**: Count
- **Buckets**: 1, 2, 4, 8, 16, 32, 64, 128
- **Labels**: None
- **Sample Collection Event**: On each successful block proposal

#### `lean_block_building_success_total` (Counter)
- **Description**: Total number of successfully built blocks.
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: None
- **Sample Collection Event**: On each successful block build

#### `lean_block_building_failures_total` (Counter)
- **Description**: Total number of failed block build attempts.
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: None
- **Sample Collection Event**: On each failed block build

### compactAttestations Metrics

#### `zeam_compact_attestations_time_seconds` (Histogram)
- **Description**: Time taken by `compactAttestations` to merge payloads sharing the same `AttestationData`.
- **Type**: Histogram
- **Unit**: Seconds
- **Buckets**: 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5
- **Labels**: None
- **Sample Collection Event**: On each invocation of `compactAttestations` during payload aggregation

#### `zeam_compact_attestations_input_total` (Counter)
- **Description**: Total number of attestations fed into `compactAttestations` before merging.
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: None
- **Sample Collection Event**: On each invocation of `compactAttestations`

#### `zeam_compact_attestations_output_total` (Counter)
- **Description**: Total number of attestations produced by `compactAttestations` after merging.
- **Type**: Counter
- **Unit**: Count (u64)
- **Labels**: None
- **Sample Collection Event**: On each invocation of `compactAttestations`


## Usage

### Importing the Package

```zig
const zeam_metrics = @import("@zeam/metrics");
```

### Initializing Metrics

Metrics must be initialized once at startup (typically in `main.zig`):

```zig
try zeam_metrics.init(allocator);
```

**Note:** On ZKVM targets, this becomes a no-op automatically.

### Using Histogram Timers

The recommended way to measure durations is using the Timer API:

```zig
// Start a timer
const timer = zeam_metrics.zeam_chain_onblock_duration_seconds.start();
defer _ = timer.observe(); // Automatically records when scope exits

// ... do work ...
// Timer is automatically recorded when function returns
```

**Benefits:**
- Automatically handles timestamp calculations
- Works on all platforms (ZKVM-safe)
- Records duration to the histogram automatically

### Using Gauges

For point-in-time measurements:

```zig
zeam_metrics.metrics.lean_head_slot.set(slot_number);
```

### Using GaugeVec

For labeled gauges, pass a label struct to `set`. Labels represent fixed dimensions — the set of possible label values is known upfront and should always be present (with value 0 when nothing is active):

```zig
zeam_metrics.metrics.lean_connected_peers.set(.{ .client = "zeam_1", .client_type = "zeam" }, 1) catch {};
```

GaugeVec and CounterVec must be initialized with an allocator:

```zig
.my_gauge_vec = try Metrics.MyGaugeVec.init(allocator, "my_gauge_vec", .{ .help = "..." }, .{}),
```

### Using Counters

For cumulative counts:

```zig
zeam_metrics.metrics.lean_state_transition_slots_processed_total.incrBy(slots_processed);
```

### Using CounterVec

For labeled counters, pass a label struct to `incr`:

```zig
zeam_metrics.metrics.lean_peer_connection_events_total.incr(.{ .direction = "inbound", .result = "success" }) catch {};
```

### Direct Histogram Observations

If you need to record a pre-calculated value without starting a timer:

```zig
zeam_metrics.lean_gossip_block_size_bytes.record(@floatFromInt(block_size_bytes));
```

## Adding New Metrics

Follow these steps to add a new metric to the system:

### Step 1: Define the Metric Type

In `pkgs/metrics/src/lib.zig`, add your metric to the `Metrics` struct:

```zig
const Metrics = struct {
    // ... existing metrics ...
    
    my_new_metric: MyNewMetricHistogram,
    
    const MyNewMetricHistogram = metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.05, 0.1, 0.5, 1.0 });
};
```

**For different metric types:**

```zig
// Histogram (for distributions)
my_histogram: metrics_lib.Histogram(f32, &[_]f32{ 0.01, 0.1, 1.0 }),

// Gauge (for point-in-time values)
my_gauge: metrics_lib.Gauge(u64),

// GaugeVec (gauge with labels — requires allocator in init)
my_gauge_vec: metrics_lib.GaugeVec(u64, struct { status: []const u8 }),

// Counter (for cumulative counts)
my_counter: metrics_lib.Counter(u64),

// CounterVec (counter with labels — requires allocator in init)
my_counter_vec: metrics_lib.CounterVec(u64, struct { direction: []const u8, result: []const u8 }),
```

### Step 2: Initialize the Metric

In the `init()` function in `pkgs/metrics/src/lib.zig`, add initialization:

```zig
pub fn init(allocator: std.mem.Allocator) !void {
    if (g_initialized) return;

    if (isZKVM()) {
        std.log.info("Using no-op metrics for ZKVM target", .{});
        g_initialized = true;
        return;
    }

    metrics = .{
        // ... existing metrics ...
        
        .my_new_metric = Metrics.MyNewMetricHistogram.init(
            "my_new_metric",
            .{ .help = "Description of what this metric measures." },
            .{}
        ),
    };

    // ... existing context assignments ...
}
```

### Step 3: Create Wrapper for Timer API (Histograms Only)

If it's a timing metric that should use the Timer API, create wrapper functions:

```zig
// Observer function
fn observeMyNewMetric(ctx: ?*anyopaque, value: f32) void {
    const histogram_ptr = ctx orelse return;
    const histogram: *Metrics.MyNewMetricHistogram = @ptrCast(@alignCast(histogram_ptr));
    histogram.observe(value);
}

// Public histogram wrapper
pub var my_new_metric: Histogram = .{
    .context = null,
    .observe = &observeMyNewMetric,
};
```

And initialize the context in `init()`:

```zig
my_new_metric.context = @ptrCast(&metrics.my_new_metric);
```

### Step 4: Use the Metric

Import the metrics package and use the metric:

```zig
const zeam_metrics = @import("@zeam/metrics");

// For timing measurements - use Timer API (recommended)
const timer = zeam_metrics.my_new_metric.start();
defer _ = timer.observe();
// ... do work ...
// Timer is automatically recorded when function returns

// For direct observations (Gauges, Counters)
zeam_metrics.metrics.my_gauge.set(42);
zeam_metrics.metrics.my_counter.incrBy(1);
```

## Best Practices

### 1. Always Use Timer API for Time Measurements

**Good:**
```zig
const timer = zeam_metrics.my_histogram.start();
defer _ = timer.observe();
// ... work ...
```

**Bad:**
```zig
const start = std.time.nanoTimestamp(); // Breaks on ZKVM!
// ... work ...
const duration = std.time.nanoTimestamp() - start;
zeam_metrics.metrics.my_histogram.observe(duration);
```

### 2. Use Appropriate Metric Types

- **Histogram**: For measuring distributions (latencies, sizes, durations)
- **Gauge**: For point-in-time values that can go up or down (queue length, temperature, slot number)
- **Counter**: For cumulative values that only increase (total requests, total errors)

### 3. Choose Meaningful Bucket Ranges

For histograms, choose buckets that capture the expected range of values:

```zig
// For sub-second latencies
&[_]f32{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0 }

// For multi-second operations
&[_]f32{ 0.5, 1, 2, 5, 10, 30, 60 }
```

### 4. Follow the Naming Convention

- `lean_` prefix: metric is defined in the [Lean metrics specification](https://github.com/leanEthereum/leanMetrics) — name, labels, buckets, and help text must match the spec exactly
- `zeam_` prefix: metric is Zeam-specific and not part of the shared spec
- Use `_total` suffix for counters: `requests_total`
- Use `_seconds` suffix for time measurements: `processing_time_seconds`
- Use base units (seconds, bytes, not milliseconds or megabytes)

### 5. Don't Block on Metrics

Metrics should never cause application logic to fail:

```zig
// Good - metrics are fire-and-forget
const timer = zeam_metrics.my_metric.start();
defer _ = timer.observe();

// The application continues even if metrics fail
```

## ZKVM and Freestanding Target Support

### Automatic Detection

The package automatically detects freestanding targets (ZKVM environments) and operates in no-op mode:

- **Host targets**: Full metrics functionality
- **Freestanding targets**: No-op metrics, no system calls compiled

### How It Works

1. **Compile-Time Checks**: Uses `comptime` to avoid compiling unsupported code
2. **No-Op Initialization**: Metrics initialize but don't allocate or record
3. **Zero Overhead**: No runtime checks, everything optimized away

```zig
fn getTimestamp() i128 {
    if (comptime isZKVM()) {
        return 0;  // No system call on ZKVM
    } else {
        return std.time.nanoTimestamp();
    }
}
```

### Why This Matters

Zero-knowledge proof environments like RISC0, SP1, OpenVM, and Zisk don't support:
- System calls (like reading time)
- Networking
- Threading
- File I/O

The metrics package is designed to work in these constrained environments without modification.

## Dependencies

This package wraps the external [karlseguin/metrics.zig](https://github.com/karlseguin/metrics.zig) library and provides:
- Application-specific metric definitions
- Timer API for convenient measurements
- ZKVM compatibility layer
- Integration with Zeam's build system

## Integration with API Package

While metrics are **defined** in this package, they are **served** via HTTP by the `@zeam/api` package:

- **This package** (`@zeam/metrics`): Defines and collects metrics
- **API package** (`@zeam/api`): Serves metrics at `/metrics` endpoint in Prometheus format

See `pkgs/api/README.md` for information about the HTTP API and metrics serving.

## Visualization

For information about visualizing metrics with Prometheus and Grafana, see the [zeam-dashboards repository](https://github.com/blockblaz/zeam-dashboards) and the API package documentation.
