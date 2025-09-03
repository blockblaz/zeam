const std = @import("std");

/// Generates a Prometheus configuration file content based on the metrics port.
/// This can be used to create a prometheus.yml file that matches the CLI arguments.
/// 
/// The generated configuration includes:
/// - Global scrape and evaluation intervals
/// - Prometheus self-monitoring target
/// - Zeam application target with the specified metrics port
/// - Optimized scrape interval for application metrics
pub fn generatePrometheusConfig(allocator: std.mem.Allocator, metrics_port: u16) ![]u8 {
    const config_template =
        "global:\n" ++
        "  scrape_interval: 15s\n" ++
        "  evaluation_interval: 15s\n" ++
        "\n" ++
        "scrape_configs:\n" ++
        "  - job_name: 'prometheus'\n" ++
        "    static_configs:\n" ++
        "      - targets: ['localhost:9090']\n" ++
        "\n" ++
        "  - job_name: 'zeam_app'\n" ++
        "    static_configs:\n" ++
        "      - targets: ['host.docker.internal:{d}']\n" ++
        "    scrape_interval: 5s\n";

    return std.fmt.allocPrint(allocator, config_template, .{metrics_port});
}
