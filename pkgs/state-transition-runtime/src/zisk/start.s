.section .text._init
# .type _start,@function
.globl _start

_start:
    .option push
    .option norelax
    la gp, _global_pointer
    .option pop

    // set the stack pointer
    la sp, _init_stack_top

    // "tail-call" to {entry}
    call main
