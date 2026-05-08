[![Lint and test](https://github.com/gballet/ssz.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/gballet/ssz.zig/actions/workflows/ci.yml)

# ssz.zig
A [Zig](https://ziglang.org) implementation of the [SSZ serialization protocol](https://github.com/ethereum/eth2.0-specs/blob/dev/ssz/simple-serialize.md).

This is meant to work with zig version 0.15.x.

## Serialization

Use `serialize` to write a serialized object to a byte buffer.

Currently supported types:

 * `BitVector[N]`
 * `uintN`
 * `boolean`
 * structures
 * optionals
 * `null`
 * `Vector[N]`
 * **tagged** unions
 * `List[N]`
 * `Bitlist[N]`

Ziglang has the limitation that it's not possible to determine which union field is active without tags.

## Deserialization

Use `deserialize` to turn a byte array containing a serialized payload, into an object.

`deserialize` does not allocate any new memory. Scalar values will be copied, and vector values use references to the serialized data. Make a copy of the data if you need to free the serialized payload. Future versions will include a version of `deserialize` that expects an allocator.

Supported types:

 * `uintN`
 * `boolean`
 * structures
 * strings
 * `BitVector[N]`
 * `Vector[N]`
 * unions
 * optionals
 * `List[N]`
 * `Bitlist[N]`

## Merkelization (experimental)

Use `tree_root_hash` to calculate the root hash of an object.

Supported types:

 * `Bitvector[N]`
 * `boolean`
 * `uintN`
 * `Vector[N]`
 * structures
 * strings
 * optionals
 * unions
 * `List[N]`
 * `Bitlist[N]`

## Using Custom Hash Functions

ssz.zig is hash-function agnostic. Pass your hasher as a type parameter:

```zig
const std = @import("std");
const ssz = @import("ssz.zig");

// Using SHA256 (from stdlib)
const Sha256 = std.crypto.hash.sha2.Sha256;
try ssz.hashTreeRoot(Sha256, MyType, value, &root, allocator);

// Using a custom hasher (must implement init/update/final API)
const MyHasher = ...; // Your hasher type
try ssz.hashTreeRoot(MyHasher, MyType, value, &root, allocator);
```

**Required Hasher API:**
```zig
pub const Options = struct {};
pub fn init(_: Options) Self;
pub fn update(self: *Self, data: []const u8) void;
pub fn final(self: *Self, out: *[Self.digest_length]u8) void; // out size matches 32 bytes for SSZ
```

## Contributing

Simply create an issue or a PR.
