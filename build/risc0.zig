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

        var write_buf = std.Io.Writer.Allocating.init(allocator);
        defer write_buf.deinit();

        // magic + binary format (risc0 format is little-endian)
        try write_buf.writer.writeAll(magic);
        try write_buf.writer.writeAll(&std.mem.toBytes(std.mem.nativeToLittle(u32, BinaryFormatVersion)));

        // write program header + len as u32
        const header = &[_]u8{ 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 5, 49, 46, 48, 46, 48 };
        try write_buf.writer.writeAll(&std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(header.len))));
        // program header
        try write_buf.writer.writeAll(header);

        // user data length + data
        try write_buf.writer.writeAll(&std.mem.toBytes(std.mem.nativeToLittle(u32, @truncate(bindata.len))));
        try write_buf.writer.writeAll(bindata);

        // DO NOT write the kernel length, it's inferred
        const kernel = try std.fs.cwd().openFile("build/v1compat.elf", .{});
        defer kernel.close();
        const kernelstat = try kernel.stat();
        const kernelsize = kernelstat.size;
        const kerneldata = try kernel.readToEndAlloc(allocator, kernelsize);
        defer allocator.free(kerneldata);
        try write_buf.writer.writeAll(kerneldata);
        try write_buf.writer.flush();

        std.debug.print("write_buf.written(): {}\n", .{write_buf.written().len});

        // write accumulated data to file
        var file_buf = std.Io.Writer.Allocating.init(allocator);
        defer file_buf.deinit();
        var file_writer = file.writer(file_buf.writer.buffer);
        try file_writer.interface.writeAll(write_buf.written());
        try file_writer.interface.flush();
    } else {
        @panic("no binary file given");
    }
}
