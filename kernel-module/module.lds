/* Linker script to discard problematic Rust sections */
SECTIONS
{
    /* Discard Rust-specific sections that cause modpost warnings */
    /DISCARD/ : {
        *(.debug_gdb_scripts)
        *(.note.GNU-stack)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
    }
}
