// CLI package library - exposes types and functions for testing and external use
// This module provides access to CLI internals without relative imports

// Re-export types from main.zig
pub const NodeCommand = @import("main.zig").NodeCommand;

// Re-export types and functions from node.zig
const node_module = @import("node.zig");
pub const Node = node_module.Node;
pub const NodeOptions = node_module.NodeOptions;
pub const buildStartOptions = node_module.buildStartOptions;

// Re-export api_server module
pub const api_server = @import("api_server.zig");

// Re-export constants module
pub const constants = @import("constants.zig");

// Re-export error handler module
pub const error_handler = @import("error_handler.zig");
