ENTRY(_start)

MEMORY
{
    RAM : ORIGIN = 0x00200000, LENGTH = 0x0FE00000
}

SECTIONS
{
    . = 0x00200000;
    PROVIDE(STACK_TOP = 0x00400000);

    .text : ALIGN(4)
    {
        *(.text .text.*)
        *(.rodata .rodata.*)
    } > RAM

    .data : ALIGN(4)
    {
        *(.data .data.*)
    } > RAM

    .bss : ALIGN(4)
    {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    } > RAM

    PROVIDE(_heap_start = . );
}
