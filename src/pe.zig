const std = @import("std");

pub const Architecture = enum {
    x86,
    x86_64,
    arm,
    arm64,
    ia64,
    unknown,

    pub fn label(self: Architecture) []const u8 {
        return switch (self) {
            .x86 => "x86",
            .x86_64 => "x86-64",
            .arm => "ARM",
            .arm64 => "ARM64",
            .ia64 => "IA-64",
            .unknown => "unknown",
        };
    }
};

pub const OptionalHeaderKind = enum { pe32, pe32_plus };

pub const Info = struct {
    machine: u16,
    architecture: Architecture,
    optional_header: OptionalHeaderKind,
};

pub const ParseError = error{
    TruncatedDosHeader,
    InvalidDosSignature,
    PeHeaderOutOfBounds,
    InvalidPeSignature,
    TruncatedOptionalHeader,
    UnsupportedOptionalHeader,
};

fn contains(bytes: []const u8, offset: usize, size: usize) bool {
    return offset <= bytes.len and size <= bytes.len - offset;
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return @as(u16, bytes[offset]) | (@as(u16, bytes[offset + 1]) << 8);
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return @as(u32, bytes[offset]) |
        (@as(u32, bytes[offset + 1]) << 8) |
        (@as(u32, bytes[offset + 2]) << 16) |
        (@as(u32, bytes[offset + 3]) << 24);
}

pub fn inspect(bytes: []const u8) ParseError!Info {
    if (bytes.len < 64) return error.TruncatedDosHeader;
    if (bytes[0] != 'M' or bytes[1] != 'Z') return error.InvalidDosSignature;

    const pe_offset_u32 = readU32(bytes, 0x3c);
    const pe_offset: usize = @intCast(pe_offset_u32);
    if (!contains(bytes, pe_offset, 4 + 20)) return error.PeHeaderOutOfBounds;
    if (bytes[pe_offset] != 'P' or bytes[pe_offset + 1] != 'E' or
        bytes[pe_offset + 2] != 0 or bytes[pe_offset + 3] != 0)
        return error.InvalidPeSignature;

    const coff_offset = pe_offset + 4;
    const machine = readU16(bytes, coff_offset);
    const optional_size: usize = readU16(bytes, coff_offset + 16);
    const optional_offset = coff_offset + 20;
    if (!contains(bytes, optional_offset, optional_size) or optional_size < 2)
        return error.TruncatedOptionalHeader;

    const kind: OptionalHeaderKind = switch (readU16(bytes, optional_offset)) {
        0x10b => .pe32,
        0x20b => .pe32_plus,
        else => return error.UnsupportedOptionalHeader,
    };
    const minimum_optional_size: usize = if (kind == .pe32) 96 else 112;
    if (optional_size < minimum_optional_size) return error.TruncatedOptionalHeader;

    return .{
        .machine = machine,
        .architecture = switch (machine) {
            0x014c => .x86,
            0x8664 => .x86_64,
            0x01c0, 0x01c4 => .arm,
            0xaa64 => .arm64,
            0x0200 => .ia64,
            else => .unknown,
        },
        .optional_header = kind,
    };
}

fn fixture(machine: u16, magic: u16, optional_size: u16) [224]u8 {
    var b: [224]u8 = @splat(0);
    b[0] = 'M';
    b[1] = 'Z';
    b[0x3c] = 64;
    b[64] = 'P';
    b[65] = 'E';
    b[68] = @truncate(machine);
    b[69] = @truncate(machine >> 8);
    b[84] = @truncate(optional_size);
    b[85] = @truncate(optional_size >> 8);
    b[88] = @truncate(magic);
    b[89] = @truncate(magic >> 8);
    return b;
}

test "recognizes x86-64 PE32+" {
    const b = fixture(0x8664, 0x20b, 112);
    const info = try inspect(&b);
    try std.testing.expectEqual(Architecture.x86_64, info.architecture);
    try std.testing.expectEqual(OptionalHeaderKind.pe32_plus, info.optional_header);
}

test "recognizes ARM64 PE32+" {
    const b = fixture(0xaa64, 0x20b, 112);
    const info = try inspect(&b);
    try std.testing.expectEqual(Architecture.arm64, info.architecture);
}

test "recognizes x86 PE32" {
    const b = fixture(0x014c, 0x10b, 96);
    const info = try inspect(&b);
    try std.testing.expectEqual(Architecture.x86, info.architecture);
    try std.testing.expectEqual(OptionalHeaderKind.pe32, info.optional_header);
}

test "rejects truncated DOS header" {
    const b: [63]u8 = @splat(0);
    try std.testing.expectError(error.TruncatedDosHeader, inspect(&b));
}

test "rejects invalid DOS signature" {
    var b = fixture(0x8664, 0x20b, 112);
    b[0] = 0;
    try std.testing.expectError(error.InvalidDosSignature, inspect(&b));
}

test "rejects out-of-bounds e_lfanew" {
    var b = fixture(0x8664, 0x20b, 112);
    b[0x3c] = 0xff;
    b[0x3d] = 0xff;
    b[0x3e] = 0xff;
    b[0x3f] = 0xff;
    try std.testing.expectError(error.PeHeaderOutOfBounds, inspect(&b));
}

test "rejects invalid PE signature" {
    var b = fixture(0x8664, 0x20b, 112);
    b[64] = 0;
    try std.testing.expectError(error.InvalidPeSignature, inspect(&b));
}

test "rejects truncated optional header" {
    var b = fixture(0x8664, 0x20b, 112);
    b[84] = 0xff;
    b[85] = 0x7f;
    try std.testing.expectError(error.TruncatedOptionalHeader, inspect(&b));
}

test "rejects undersized optional header" {
    const b = fixture(0x8664, 0x20b, 40);
    try std.testing.expectError(error.TruncatedOptionalHeader, inspect(&b));
}

test "rejects unsupported optional header magic" {
    const b = fixture(0x8664, 0x777, 40);
    try std.testing.expectError(error.UnsupportedOptionalHeader, inspect(&b));
}
