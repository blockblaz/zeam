OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(mips)
ENTRY(__start)

MEMORY {
  ram (rwx) : ORIGIN = 0x00400000, LENGTH = 0x7EC00000
}

SECTIONS {
  . = 0x00400000;

  .text : ALIGN(4) {
    *(.text._start)
    *(.text .text.*)
  } >ram

  . = ALIGN(4);

  .rodata : ALIGN(4) {
    *(.rodata .rodata.*)
  } >ram

  . = ALIGN(4);

  .data : ALIGN(4) {
    *(.data .data.*)
    _gp = . + 0x8000;
    *(.sdata .sdata.*)
  } >ram

  . = ALIGN(4);

  .bss (NOLOAD) : ALIGN(4) {
    __bss_start = .;
    *(.bss .bss.*)
    *(.sbss .sbss.*)
    *(COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } >ram

  _end = .;

  _heap_end = 0x7E000000;
  _stack_top = 0x7F000000;

  /DISCARD/ : {
    *(.comment)
    *(.eh_frame)
    *(.MIPS.abiflags)
    *(.reginfo)
    *(.pdr)
  }
}
