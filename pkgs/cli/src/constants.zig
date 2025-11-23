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

/// Default node key file path
pub const DEFAULT_NODE_KEY: []const u8 = "./key";

/// Maximum size (in bytes) for hash-sig key JSON blobs ingested by the CLI
pub const MAX_HASH_SIG_KEY_JSON_SIZE: usize = 128 * 1024 * 1024;
