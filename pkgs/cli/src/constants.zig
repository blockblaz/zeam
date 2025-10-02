const std = @import("std");

/// Default port for metrics server
pub const DEFAULT_METRICS_PORT: u16 = 9667;

/// Default server IP address for local connections
pub const DEFAULT_SERVER_IP: []const u8 = "127.0.0.1";

/// Default timeout for server startup (in milliseconds)
pub const DEFAULT_SERVER_STARTUP_TIMEOUT_MS: i64 = 120000;

/// Default retry interval between connection attempts (in milliseconds)
pub const DEFAULT_RETRY_INTERVAL_MS: u64 = 1000;

/// Default path for the data directory
pub const DEFAULT_DATA_DIR: []const u8 = "./data";

/// SSE heartbeat interval (seconds)
pub const SSE_HEARTBEAT_SECONDS: u64 = 30;
