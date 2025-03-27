pub const syscalls = enum {
    halt,
    input,
    software,
    sha,
    bigint,
    user,
    bigint2,
    poseidon2,
};

pub const halt_reason = enum {
    terminate,
    pause,
    split,
};

pub const keccak_mode = enum {
    permute,
    prove,
};
