const std = @import("std");

const magic = "R0BF";
const BinaryFormatVersion = 1;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = std.heap.page_allocator;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len > 1) {
        const srcfile = args[1];
        std.debug.print("Post-processing {s}\n", .{srcfile});

        const cwd = std.Io.Dir.cwd();
        const bindata = try cwd.readFileAlloc(io, srcfile, allocator, .limited(std.math.maxInt(usize)));
        defer allocator.free(bindata);

        const dir = std.fs.path.dirname(srcfile).?;
        const output_path = try std.fs.path.join(allocator, &[_][]const u8{ dir, "risc0_runtime.elf" });
        defer allocator.free(output_path);

        const file = try cwd.createFile(io, output_path, .{ .truncate = true });
        defer file.close(io);

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
        const kerneldata = try cwd.readFileAlloc(io, "build/v1compat.elf", allocator, .limited(std.math.maxInt(usize)));
        defer allocator.free(kerneldata);
        try write_buf.writer.writeAll(kerneldata);
        try write_buf.writer.flush();

        std.debug.print("write_buf.written(): {}\n", .{write_buf.written().len});

        // write accumulated data to file
        var file_buf = std.Io.Writer.Allocating.init(allocator);
        defer file_buf.deinit();
        var file_writer = file.writer(io, file_buf.writer.buffer);
        try file_writer.interface.writeAll(write_buf.written());
        try file_writer.interface.flush();
    } else {
        @panic("no binary file given");
    }
}
