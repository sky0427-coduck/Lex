const std = @import("std");
const pe = @import("pe.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len != 2) {
        std.debug.print("Usage: lex-pe-inspector <file.exe|file.dll>\n", .{});
        return error.InvalidArguments;
    }

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        args[1],
        allocator,
        .limited(256 * 1024 * 1024),
    ) catch |err| {
        std.debug.print("Could not read '{s}': {s}\n", .{ args[1], @errorName(err) });
        return err;
    };

    const info = pe.inspect(bytes) catch |err| {
        std.debug.print("Invalid or unsupported PE file '{s}': {s}\n", .{ args[1], @errorName(err) });
        return err;
    };

    std.debug.print("File: {s}\nArchitecture: {s} (COFF machine 0x{x:0>4})\nOptional header: {s}\n", .{
        args[1],
        info.architecture.label(),
        info.machine,
        if (info.optional_header == .pe32) "PE32" else "PE32+",
    });
}
