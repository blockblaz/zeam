const magic = "R0BF";
const std = @import("std");

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
        const writer = file.writer();

        // magic +  binary format
        _ = try writer.write(magic);
        try writer.writeInt(u32, 1, .little);

        // write program header + len as u32

        // user data length + data
        try writer.writeInt(u32, @truncate(bindata.len), .little);
        _ = try writer.write(bindata);

        // DO NOT write the kernel lenght, it's inferred
    } else {
        @panic("no binary file given");
    }
}
