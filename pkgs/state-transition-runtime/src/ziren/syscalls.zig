// Ziren (zkMIPS) syscall definitions.
//
// Syscall ABI: number in $v0 ($2), arguments in $a0-$a3 ($4-$7),
// return value in $v0 ($2). Invoked via the MIPS `syscall` instruction.

// Syscall numbers
pub const HALT: u32 = 0x00000000;
pub const WRITE: u32 = 0x00000002;
pub const ENTER_UNCONSTRAINED: u32 = 0x0000000C;
pub const EXIT_UNCONSTRAINED: u32 = 0x0000000D;
pub const COMMIT: u32 = 0x00000010;
pub const SYSHINTLEN: u32 = 0x000000F0;
pub const SYSHINTREAD: u32 = 0x000000F1;
pub const SYSVERIFY: u32 = 0x000000F2;
pub const SHA_EXTEND: u32 = 0x30010005;
pub const SHA_COMPRESS: u32 = 0x00010006;
pub const KECCAK_SPONGE: u32 = 0x01010009;

// File descriptor constants
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_PUBLIC_VALUES: u32 = 4;
pub const FD_HINT: u32 = 5;

pub inline fn syscall_0(num: u32) u32 {
    return asm volatile ("syscall"
        : [ret] "={$2}" (-> u32),
        : [num] "{$2}" (num),
        : "$1", "$3", "$7", "$8", "$9", "$10", "$11",
          "$12", "$13", "$14", "$15", "$24", "$25", "memory",
    );
}

pub inline fn syscall_1(num: u32, a0: u32) u32 {
    return asm volatile ("syscall"
        : [ret] "={$2}" (-> u32),
        : [num] "{$2}" (num),
          [a0] "{$4}" (a0),
        : "$1", "$3", "$7", "$8", "$9", "$10", "$11",
          "$12", "$13", "$14", "$15", "$24", "$25", "memory",
    );
}

pub inline fn syscall_2(num: u32, a0: u32, a1: u32) u32 {
    return asm volatile ("syscall"
        : [ret] "={$2}" (-> u32),
        : [num] "{$2}" (num),
          [a0] "{$4}" (a0),
          [a1] "{$5}" (a1),
        : "$1", "$3", "$7", "$8", "$9", "$10", "$11",
          "$12", "$13", "$14", "$15", "$24", "$25", "memory",
    );
}

pub inline fn syscall_3(num: u32, a0: u32, a1: u32, a2: u32) u32 {
    return asm volatile ("syscall"
        : [ret] "={$2}" (-> u32),
        : [num] "{$2}" (num),
          [a0] "{$4}" (a0),
          [a1] "{$5}" (a1),
          [a2] "{$6}" (a2),
        : "$1", "$3", "$7", "$8", "$9", "$10", "$11",
          "$12", "$13", "$14", "$15", "$24", "$25", "memory",
    );
}

pub inline fn syscall_noreturn(num: u32, a0: u32) noreturn {
    asm volatile ("syscall"
        :
        : [num] "{$2}" (num),
          [a0] "{$4}" (a0),
        : "$1", "$3", "$7", "$8", "$9", "$10", "$11",
          "$12", "$13", "$14", "$15", "$24", "$25", "memory",
    );
    unreachable;
}
