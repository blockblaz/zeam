.section .text._init
.globl _start

_start:
    .option push
    .option norelax
    lla gp, _global_pointer
    .option pop

    // set the stack pointer
    lla sp, _init_stack_top

    // "tail-call" to {entry}
    tail main
