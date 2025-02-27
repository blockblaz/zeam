pub const io = @import("./io.zig");
pub const syscalls = @import("./syscalls.zig");
const syscall_halt = syscalls.HALT;
const syscall_commit = syscalls.COMMIT;

extern fn main() noreturn;

export fn __start() noreturn {
    // PUBLIC_VALUES_HASHER = Some(Sha256::new());
    // #[cfg(feature = "verify")]
    // {
    //     DEFERRED_PROOFS_DIGEST = Some([BabyBear::zero(); 8]);
    // }

    main();
}

pub fn halt(_: u32) noreturn {
    const exit_code = 0; // make it an interface param if that makes sense

    asm volatile ("ecall"
        : [syscall_num] "{t0}" (syscall_halt),
          [exit_code] "{a0}" (exit_code),
    );
    unreachable;
}
