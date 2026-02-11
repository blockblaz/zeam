const std = @import("std");

const magic = "R0BF";
const BinaryFormatVersion = 1;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var args = std.process.args();
    _ = args.next(); // skip self name
    if (args.next()) |srcfile| {
        std.debug.print("Post-processing {s}\n", .{srcfile});

        const src = try std.fs.cwd().openFile(srcfile, .{});
        defer src.close();
        const srcstat = try src.stat();
        const srcsize = srcstat.size;
        const bindata = try src.readToEndAlloc(allocator, srcsize);

        const dir = std.fs.path.dirname(srcfile).?;
        const output_path = try std.fs.path.join(allocator, &[_][]const u8{ dir, "risc0_runtime.elf" });
        defer allocator.free(output_path);

        const file = try std.fs.cwd().createFile(output_path, .{ .truncate = true });
        defer file.close();

        var write_buf: [131072]u8 = undefined;
        var writer = file.writer(&write_buf);

        // magic + binary format (risc0 format is little-endian)
        try writer.interface.writeAll(magic);
        try writer.interface.writeAll(&std.mem.toBytes(std.mem.nativeToLittle(u32, BinaryFormatVersion)));

        // write program header + len as u32
        const header = &[_]u8{ 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 5, 49, 46, 48, 46, 48 };
        try writer.interface.writeAll(&std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(header.len))));
        // program header
        try writer.interface.writeAll(header);

        // user data length + data
        try writer.interface.writeAll(&std.mem.toBytes(std.mem.nativeToLittle(u32, @truncate(bindata.len))));
        try writer.interface.writeAll(bindata);

        // DO NOT write the kernel length, it's inferred
        const kernel = try std.fs.cwd().openFile("build/v1compat.elf", .{});
        defer kernel.close();
        const kernelstat = try kernel.stat();
        const kernelsize = kernelstat.size;
        const kerneldata = try kernel.readToEndAlloc(allocator, kernelsize);
        defer allocator.free(kerneldata);
        try writer.interface.writeAll(kerneldata);
        try writer.interface.flush();
    } else {
        @panic("no binary file given");
    }
}
