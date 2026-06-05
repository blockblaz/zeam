//! cgroup-aware logical CPU count for Linux.
//!
//! `std.Thread.getCpuCount()` only reads the CPU affinity mask and is blind to
//! the cgroup CFS quota (`cpu.max` / `cpu.cfs_quota_us`), so under
//! `docker --cpus=N` or k8s `limits.cpu` it reports the host core count. This
//! returns `min(quota, affinity)` instead, matching `os.availableParallelism()`.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const log = std.log.scoped(.cpu_count);

const CgroupVersion = enum { v1, v2 };

/// cgroup-aware logical CPU count: `min(cgroup quota, affinity)`, or the affinity
/// count when no quota applies. Drop-in for `std.Thread.getCpuCount()` when
/// sizing a thread pool. `gpa` is used only for two short-lived `/proc` reads
/// on Linux (none on other platforms or when there is no quota).
pub fn getNumCpus(gpa: Allocator, io: Io) usize {
    const logical = logicalCpus();
    const result = if (cgroupsNumCpus(gpa, io)) |quota| @min(quota, logical) else logical;

    assert(result >= 1);
    assert(result <= logical);
    return result;
}

/// Logical CPU count from the affinity mask.
fn logicalCpus() usize {
    const n = std.Thread.getCpuCount() catch 1;
    assert(n >= 1);
    return n;
}

/// The cgroup CPU quota as an effective core count (Linux only): locate the cpu
/// controller via `/proc/self/{cgroup,mountinfo}`, then read its quota files.
fn cgroupsNumCpus(gpa: Allocator, io: Io) ?usize {
    if (builtin.os.tag != .linux) return null;

    const cwd = Io.Dir.cwd();

    // Only the /proc reads themselves are worth warning about: failing to read
    // them on Linux means a real quota could be silently missed (the pool may
    // over-size in a CPU-limited container). Parse-level misses below are the
    // benign "no limit applies" cases (no cpu controller, cpu.max == "max").
    const cgroup = readProcFile(gpa, io, cwd, "/proc/self/cgroup", .limited(1 << 20)) orelse {
        log.warn("failed to read /proc/self/cgroup; sizing by affinity CPU count", .{});
        return null;
    };
    defer gpa.free(cgroup);

    const mountinfo = readProcFile(gpa, io, cwd, "/proc/self/mountinfo", .limited(8 << 20)) orelse {
        log.warn("failed to read /proc/self/mountinfo; sizing by affinity CPU count", .{});
        return null;
    };
    defer gpa.free(mountinfo);

    const subsys = Subsys.load(cgroup) orelse return null;
    const mnt = MountInfo.load(mountinfo, subsys.version) orelse return null;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = translate(mnt.root, mnt.mount_point, subsys.base, &path_buf) orelse return null;

    var dir = cwd.openDir(io, base, .{}) catch return null;
    defer dir.close(io);

    const quota = cpuQuotaFromDir(io, dir, subsys.version) orelse return null;
    if (quota == 0) return null; // no usable limit; fall back to affinity
    return quota;
}

/// Read a `/proc` pseudo-file whole; the caller owns the result. `/proc` reports
/// size 0, so stream to EOF rather than doing a size-based read. Returns null
/// past `limit` (`error.StreamTooLong`) rather than truncating.
fn readProcFile(gpa: Allocator, io: Io, dir: Io.Dir, sub_path: []const u8, limit: Io.Limit) ?[]u8 {
    assert(sub_path.len > 0);

    var file = dir.openFile(io, sub_path, .{}) catch return null;
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    return reader.interface.allocRemaining(gpa, limit) catch null;
}

/// CPU quota from an open cgroup directory, as an effective core count.
fn cpuQuotaFromDir(io: Io, dir: Io.Dir, version: CgroupVersion) ?usize {
    switch (version) {
        .v2 => {
            var buf: [128]u8 = undefined;
            const content = dir.readFile(io, "cpu.max", &buf) catch return null;
            return parseCpuMaxV2(content);
        },
        .v1 => {
            var quota_buf: [64]u8 = undefined;
            var period_buf: [64]u8 = undefined;
            const quota = dir.readFile(io, "cpu.cfs_quota_us", &quota_buf) catch return null;
            const period = dir.readFile(io, "cpu.cfs_period_us", &period_buf) catch return null;
            return parseCpuV1(quota, period);
        },
    }
}

/// Host path of the cgroup directory: strip the mount's internal `root` from
/// `subsys_base` by path component, then join the remainder onto `mount_point`,
/// writing into `out`. Returns null if `subsys_base` is not under `root` —
/// component boundaries are respected, so `/docker/abc-x` is not under
/// `/docker/abc`.
fn translate(root: []const u8, mount_point: []const u8, subsys_base: []const u8, out: []u8) ?[]const u8 {
    var root_it = std.mem.tokenizeScalar(u8, root, '/');
    var base_it = std.mem.tokenizeScalar(u8, subsys_base, '/');

    while (root_it.next()) |rc| {
        const bc = base_it.next() orelse return null; // base shorter than root
        if (!std.mem.eql(u8, rc, bc)) return null; // component mismatch
    }

    if (mount_point.len > out.len) return null;
    @memcpy(out[0..mount_point.len], mount_point);
    var len: usize = mount_point.len;

    while (base_it.next()) |bc| {
        if (len + 1 + bc.len > out.len) return null;
        out[len] = '/';
        len += 1;
        @memcpy(out[len..][0..bc.len], bc);
        len += bc.len;
    }

    assert(len <= out.len);
    return out[0..len];
}

/// The cpu controller entry from `/proc/self/cgroup`.
const Subsys = struct {
    version: CgroupVersion,
    base: []const u8,

    /// Parse one line, e.g. `11:cpu,cpuacct:/foo` (v1) or `0::/foo` (v2).
    /// Null if the line is not the cpu controller.
    fn parseLine(line: []const u8) ?Subsys {
        var it = std.mem.splitScalar(u8, line, ':');
        _ = it.next() orelse return null; // hierarchy id
        const subsystems = it.next() orelse return null;
        const base = it.next() orelse return null;

        const version: CgroupVersion = if (subsystems.len == 0) .v2 else .v1;
        if (version == .v1 and !hasCsvItem(subsystems, "cpu")) return null;
        return .{ .version = version, .base = base };
    }

    /// First cpu controller across all lines; a v1 entry takes precedence over v2.
    fn load(content: []const u8) ?Subsys {
        var result: ?Subsys = null;
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            const s = Subsys.parseLine(line) orelse continue;
            if (result != null and s.version == .v2) continue; // v2 never overwrites
            result = s;
        }
        return result;
    }
};

/// The cgroup mount entry from `/proc/self/mountinfo`.
const MountInfo = struct {
    version: CgroupVersion,
    root: []const u8,
    mount_point: []const u8,

    /// Parse one line: `id pid dev root mount_point opts... - fstype src opts`.
    /// v1 additionally requires the `cpu` super option.
    fn parseLine(line: []const u8) ?MountInfo {
        var it = std.mem.splitScalar(u8, line, ' ');
        _ = it.next() orelse return null; // mount id
        _ = it.next() orelse return null; // parent id
        _ = it.next() orelse return null; // major:minor
        const root = it.next() orelse return null;
        const mount_point = it.next() orelse return null;

        // Skip the variable number of optional fields up to the "-" separator.
        while (it.next()) |f| {
            if (std.mem.eql(u8, f, "-")) break;
        } else return null;

        const fstype = it.next() orelse return null;
        const version: CgroupVersion = if (std.mem.eql(u8, fstype, "cgroup"))
            .v1
        else if (std.mem.eql(u8, fstype, "cgroup2"))
            .v2
        else
            return null;

        if (version == .v1) {
            _ = it.next() orelse return null; // mount source
            const super_opts = it.next() orelse return null;
            if (!hasCsvItem(super_opts, "cpu")) return null;
        }
        return .{ .version = version, .root = root, .mount_point = mount_point };
    }

    /// First mount of the requested version.
    fn load(content: []const u8, version: CgroupVersion) ?MountInfo {
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            const m = MountInfo.parseLine(line) orelse continue;
            if (m.version == version) return m;
        }
        return null;
    }
};

/// Parse a v2 `cpu.max` value (`<quota> <period>` or `max <period>`) to
/// `ceil(quota/period)` effective CPUs. Null when unlimited, malformed, or the
/// period is zero.
pub fn parseCpuMaxV2(content: []const u8) ?usize {
    var it = std.mem.tokenizeAny(u8, content, " \t\r\n");
    const quota_s = it.next() orelse return null;
    const period_s = it.next() orelse return null;

    if (std.mem.eql(u8, quota_s, "max")) return null; // unlimited
    const quota = std.fmt.parseUnsigned(u64, quota_s, 10) catch return null;
    const period = std.fmt.parseUnsigned(u64, period_s, 10) catch return null;
    if (period == 0) return null;
    return ceilDiv(quota, period);
}

/// Parse v1 `cpu.cfs_quota_us` + `cpu.cfs_period_us` to `ceil(quota/period)`.
/// Null when unlimited (quota `-1`), malformed, or the period is zero.
pub fn parseCpuV1(quota_text: []const u8, period_text: []const u8) ?usize {
    const q = std.mem.trim(u8, quota_text, " \t\r\n");
    const p = std.mem.trim(u8, period_text, " \t\r\n");

    // "-1" (unlimited) fails to parse as unsigned -> null.
    const quota = std.fmt.parseUnsigned(u64, q, 10) catch return null;
    const period = std.fmt.parseUnsigned(u64, p, 10) catch return null;
    if (period == 0) return null;
    return ceilDiv(quota, period);
}

/// `ceil(n / d)` for `n, d > 0`. Uses `(n - 1) / d + 1` so the numerator cannot
/// overflow, and saturates the `usize` cast so an adversarial value can never
/// panic. Caller guarantees `d != 0`.
fn ceilDiv(n: u64, d: u64) usize {
    assert(d != 0);
    if (n == 0) return 0;

    const q = (n - 1) / d + 1;
    assert(q >= 1);
    return std.math.cast(usize, q) orelse std.math.maxInt(usize);
}

/// Whether `item` is one of the comma-separated entries in `csv`.
fn hasCsvItem(csv: []const u8, item: []const u8) bool {
    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |x| {
        if (std.mem.eql(u8, x, item)) return true;
    }
    return false;
}

// ===========================================================================
// Tests
// ===========================================================================

// Test fixtures: synthetic single lines + realistic full /proc samples.
const mnt_v1 = "7 5 0:6 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:7 - cgroup cgroup rw,cpu,cpuacct";
const mnt_v1_zero_opt = "7 5 0:6 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu,cpuacct";
const mnt_v1_multi_opt = "7 5 0:6 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:7 master:2 - cgroup cgroup rw,cpu,cpuacct";
const mnt_v1_no_cpu = "8 5 0:7 / /sys/fs/cgroup/memory rw,nosuid shared:8 - cgroup cgroup rw,memory";
const mnt_v2 = "30 25 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:4 - cgroup2 cgroup2 rw,nsdelegate";
const cpu_mount = "/sys/fs/cgroup/cpu,cpuacct";
// Realistic `/proc` samples (v1, v2, and the optional-field / good / ceil /
// zero-period variants), covering the full parse-and-resolve pipeline.
const sample_v1_cgroup = "12:perf_event:/\n11:cpu,cpuacct:/\n3:devices:/user.slice\n";
const sample_v1_mountinfo = "1 0 8:1 / / rw,noatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro,data=reordered\n2 1 0:1 / /dev rw,relatime shared:2 - devtmpfs udev rw,size=10240k,nr_inodes=16487629,mode=755\n3 1 0:2 / /proc rw,nosuid,nodev,noexec,relatime shared:3 - proc proc rw\n4 1 0:3 / /sys rw,nosuid,nodev,noexec,relatime shared:4 - sysfs sysfs rw\n5 4 0:4 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:5 - tmpfs tmpfs ro,mode=755\n6 5 0:5 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:6 - cgroup cgroup rw,cpuset\n7 5 0:6 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:7 - cgroup cgroup rw,cpu,cpuacct\n8 5 0:7 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:8 - cgroup cgroup rw,memory\n";
const sample_v1_mountinfo_zero = "1 0 8:1 / / rw,noatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro,data=reordered\n2 1 0:1 / /dev rw,relatime shared:2 - devtmpfs udev rw,size=10240k,nr_inodes=16487629,mode=755\n3 1 0:2 / /proc rw,nosuid,nodev,noexec,relatime shared:3 - proc proc rw\n4 1 0:3 / /sys rw,nosuid,nodev,noexec,relatime shared:4 - sysfs sysfs rw\n5 4 0:4 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:5 - tmpfs tmpfs ro,mode=755\n6 5 0:5 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:6 - cgroup cgroup rw,cpuset\n7 5 0:6 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu,cpuacct\n8 5 0:7 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:8 - cgroup cgroup rw,memory\n";
const sample_v1_mountinfo_multi = "1 0 8:1 / / rw,noatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro,data=reordered\n2 1 0:1 / /dev rw,relatime shared:2 - devtmpfs udev rw,size=10240k,nr_inodes=16487629,mode=755\n3 1 0:2 / /proc rw,nosuid,nodev,noexec,relatime shared:3 - proc proc rw\n4 1 0:3 / /sys rw,nosuid,nodev,noexec,relatime shared:4 - sysfs sysfs rw\n5 4 0:4 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:5 - tmpfs tmpfs ro,mode=755\n6 5 0:5 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:6 - cgroup cgroup rw,cpuset\n7 5 0:6 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:7 shared:8 shared:9 - cgroup cgroup rw,cpu,cpuacct\n8 5 0:7 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:8 - cgroup cgroup rw,memory\n";
const sample_v2_cgroup = "12::/\n3::/user.slice\n";
const sample_v2_cgroup_multi = "12::/\n11:cpu,cpuacct:/\n3::/user.slice\n";
const sample_v2_mountinfo = "1 0 8:1 / / rw,noatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro,data=reordered\n2 1 0:1 / /dev rw,relatime shared:2 - devtmpfs udev rw,size=10240k,nr_inodes=16487629,mode=755\n3 1 0:2 / /proc rw,nosuid,nodev,noexec,relatime shared:3 - proc proc rw\n4 1 0:3 / /sys rw,nosuid,nodev,noexec,relatime shared:4 - sysfs sysfs rw\n5 4 0:4 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:5 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n";
// Quota files keep their double trailing newline, to exercise the trimming.
const sample_v1_good_quota = "600000\n\n";
const sample_v1_good_period = "100000\n\n";
const sample_v1_ceil_quota = "150000\n\n";
const sample_v1_ceil_period = "100000\n\n";
const sample_v1_zero_quota = "600000\n";
const sample_v1_zero_period = "0\n\n";
const sample_v2_good_max = "600000 100000\n";
const sample_v2_ceil_max = "150000 100000\n";
const sample_v2_zero_max = "600000 0\n";

test "parseCpuMaxV2" {
    const cases = .{
        .{ "200000 100000", @as(?usize, 2) },
        .{ "150000 100000", @as(?usize, 2) }, // rounds up
        .{ "200000 100000\n", @as(?usize, 2) }, // trailing newline tolerated
        .{ "600000 100000", @as(?usize, 6) },
        .{ "max 100000", @as(?usize, null) }, // unlimited
        .{ "100000 0", @as(?usize, null) }, // zero period
    };
    inline for (cases) |c| {
        try std.testing.expectEqual(c[1], parseCpuMaxV2(c[0]));
    }
}
test "parseCpuMaxV2: huge quota does not overflow" {
    try std.testing.expect(parseCpuMaxV2("18446744073709551615 2") != null);
}

test "parseCpuV1" {
    const cases = .{
        .{ "200000", "100000", @as(?usize, 2) },
        .{ "150000\n", "100000\n", @as(?usize, 2) }, // rounds up + trims
        .{ "600000", "100000", @as(?usize, 6) },
        .{ "-1", "100000", @as(?usize, null) }, // unlimited
        .{ "100000", "0", @as(?usize, null) }, // zero period
    };
    inline for (cases) |c| {
        try std.testing.expectEqual(c[2], parseCpuV1(c[0], c[1]));
    }
}

fn expectSubsys(got: ?Subsys, version: ?CgroupVersion, base: []const u8) !void {
    if (version) |v| {
        try std.testing.expect(got != null);
        try std.testing.expectEqual(v, got.?.version);
        try std.testing.expectEqualStrings(base, got.?.base);
    } else {
        try std.testing.expect(got == null);
    }
}

test "Subsys.parseLine" {
    try expectSubsys(Subsys.parseLine("11:cpu,cpuacct:/docker/01abcd"), .v1, "/docker/01abcd");
    try expectSubsys(Subsys.parseLine("0::/foo"), .v2, "/foo");
    try expectSubsys(Subsys.parseLine("5:memory:/foo"), null, ""); // no cpu controller
}
test "Subsys.load" {
    try expectSubsys(Subsys.load("0::/v2path\n11:cpu,cpuacct:/v1path"), .v1, "/v1path"); // v1 trumps v2
    try expectSubsys(Subsys.load("12:cpuset:/\n0::/unified"), .v2, "/unified");
    try expectSubsys(Subsys.load(sample_v1_cgroup), .v1, "/");
    try expectSubsys(Subsys.load(sample_v2_cgroup), .v2, "/");
    try expectSubsys(Subsys.load(sample_v2_cgroup_multi), .v1, "/"); // v1 wins
}

fn expectMount(got: ?MountInfo, version: ?CgroupVersion, root: []const u8, mount_point: []const u8) !void {
    if (version) |v| {
        try std.testing.expect(got != null);
        try std.testing.expectEqual(v, got.?.version);
        try std.testing.expectEqualStrings(root, got.?.root);
        try std.testing.expectEqualStrings(mount_point, got.?.mount_point);
    } else {
        try std.testing.expect(got == null);
    }
}

test "MountInfo.parseLine" {
    try expectMount(MountInfo.parseLine(mnt_v1), .v1, "/", cpu_mount);
    try expectMount(MountInfo.parseLine(mnt_v1_zero_opt), .v1, "/", cpu_mount);
    try expectMount(MountInfo.parseLine(mnt_v1_multi_opt), .v1, "/", cpu_mount);
    try expectMount(MountInfo.parseLine(mnt_v1_no_cpu), null, "", ""); // no cpu super-opt
    try expectMount(MountInfo.parseLine(mnt_v2), .v2, "/", "/sys/fs/cgroup");
}
test "MountInfo.load" {
    try expectMount(MountInfo.load(mnt_v1_no_cpu ++ "\n" ++ mnt_v2, .v2), .v2, "/", "/sys/fs/cgroup");
    inline for (.{ sample_v1_mountinfo, sample_v1_mountinfo_zero, sample_v1_mountinfo_multi }) |content| {
        try expectMount(MountInfo.load(content, .v1), .v1, "/", cpu_mount);
    }
    try expectMount(MountInfo.load(sample_v2_mountinfo, .v2), .v2, "/", "/sys/fs/cgroup");
}

fn expectTranslate(root: []const u8, mp: []const u8, base: []const u8, expected: ?[]const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const got = translate(root, mp, base, &buf);
    if (expected) |exp| {
        try std.testing.expect(got != null);
        try std.testing.expectEqualStrings(exp, got.?);
    } else {
        try std.testing.expect(got == null);
    }
}

test "translate: mount path cases" {
    try expectTranslate("/", "/sys/fs/cgroup/cpu", "/", "/sys/fs/cgroup/cpu");
    try expectTranslate("/docker/01abcd", "/sys/fs/cgroup/cpu", "/docker/01abcd", "/sys/fs/cgroup/cpu");
    try expectTranslate("/docker/01abcd", "/sys/fs/cgroup/cpu", "/docker/01abcd/", "/sys/fs/cgroup/cpu");
    try expectTranslate("/docker/01abcd", "/sys/fs/cgroup/cpu", "/docker/01abcd/large", "/sys/fs/cgroup/cpu/large");
    try expectTranslate("/docker/01abcd", "/sys/fs/cgroup/cpu", "/", null);
    try expectTranslate("/docker/01abcd", "/sys/fs/cgroup/cpu", "/docker", null);
    try expectTranslate("/docker/01abcd", "/sys/fs/cgroup/cpu", "/elsewhere", null);
    try expectTranslate("/docker/01abcd", "/sys/fs/cgroup/cpu", "/docker/01abcd-other-dir", null);
}

test "cpuQuotaFromDir: v2" {
    const cases = .{
        .{ "200000 100000\n", @as(?usize, 2) },
        .{ sample_v2_good_max, @as(?usize, 6) },
        .{ sample_v2_ceil_max, @as(?usize, 2) },
        .{ sample_v2_zero_max, @as(?usize, null) },
    };
    inline for (cases) |c| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cpu.max", .data = c[0] });
        try std.testing.expectEqual(c[1], cpuQuotaFromDir(std.testing.io, tmp.dir, .v2));
    }
}
test "cpuQuotaFromDir: v1" {
    const cases = .{
        .{ "300000\n", "100000\n", @as(?usize, 3) },
        .{ sample_v1_good_quota, sample_v1_good_period, @as(?usize, 6) },
        .{ sample_v1_ceil_quota, sample_v1_ceil_period, @as(?usize, 2) },
        .{ sample_v1_zero_quota, sample_v1_zero_period, @as(?usize, null) },
    };
    inline for (cases) |c| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cpu.cfs_quota_us", .data = c[0] });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cpu.cfs_period_us", .data = c[1] });
        try std.testing.expectEqual(c[2], cpuQuotaFromDir(std.testing.io, tmp.dir, .v1));
    }
}
test "cpuQuotaFromDir: missing file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectEqual(@as(?usize, null), cpuQuotaFromDir(std.testing.io, tmp.dir, .v2));
}

test "readProcFile: streams a size-unknown file fully" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "f", .data = "11:cpu:/\n" });

    const got = readProcFile(std.testing.allocator, std.testing.io, tmp.dir, "f", .limited(1 << 20)).?;
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualStrings("11:cpu:/\n", got);
}
test "readProcFile: null past limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "f", .data = "a" ** (100 * 1024) });
    try std.testing.expect(readProcFile(std.testing.allocator, std.testing.io, tmp.dir, "f", .limited(64 * 1024)) == null);
}

test "getNumCpus: at least 1" {
    try std.testing.expect(getNumCpus(std.testing.allocator, std.testing.io) >= 1);
}
test "getNumCpus: never exceeds logical" {
    try std.testing.expect(getNumCpus(std.testing.allocator, std.testing.io) <= logicalCpus());
}
