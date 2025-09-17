const partialFactory = @import("./partial.zig");
pub usingnamespace partialFactory;

const mixFactory = @import("./mixin.zig");
pub usingnamespace mixFactory;

const castFactory = @import("./cast.zig");
pub usingnamespace castFactory;

const logFactory = @import("./log.zig");
pub usingnamespace logFactory;

const yaml_factory = @import("./yaml.zig");
// Avoid to use `usingnamespace` to make upgrade easier in the future.
pub const loadFromYAMLFile = yaml_factory.loadFromYAMLFile;

const fs_factory = @import("./fs.zig");
// Avoid to use `usingnamespace` to make upgrade easier in the future.
pub const checkDIRExists = fs_factory.checkDIRExists;
pub const readFileToEndAlloc = fs_factory.readFileToEndAlloc;

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
