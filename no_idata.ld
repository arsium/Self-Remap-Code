
SECTIONS
{
  . = SIZEOF_HEADERS;
  . = ALIGN(__section_alignment__);
  .text __image_base__ + ( __section_alignment__ < 0x1000 ? . : __section_alignment__ ) :
  {
    *(.text)
    *(.data)
    *(.rdata)
    *(SORT(.rdata$*))
    KEEP(*(.pdata*))
    *(.bss)
    *(.idata)
    *(SORT(.idata$*))
    *(.text*) /* Ensure .text matches only regular text sections */
  }

  /DISCARD/ :
    {
        *(.text.un)    /* Unused code */
        *(.xdata)      /* Exception data */
        *(.pdata)      /* Unused pdata */
        *(.rdata$*)    /* rdata subsections */
        *(.eh_frame)   /* GCC exception handling */
        *(.gcc_except_table)
        *(.eh_frame_hdr)
    }
}