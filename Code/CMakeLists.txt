cmake_minimum_required(VERSION 3.29)
project(self_rewrite C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Os -s -fno-ident -fno-asynchronous-unwind-tables -fno-builtin -ffreestanding -mconsole -mnop-fun-dllimport -O2 -std=gnu89 ")
#align section with 0x10000 (64kb)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -Wl,--section-alignment=0x10000")
add_executable(self_rewrite main.c POC.c POC.h HostileHeader.h)

# Combine all compiler flags into a single add_compile_options
add_compile_options(
        -ffreestanding                      # Avoid assumptions about standard library
        -fno-builtin                        # Disable GCC built-in functions
        -fno-ident                          # Remove identifying metadata
        -fno-asynchronous-unwind-tables     # Disable unwind tables for exceptions
        -Os                                 # Optimize for size
        -O2
        -std=gnu89
        -mconsole                          # Indicate Windows application -mwindows (use -mconsole for console apps)
)

# Linker options to exclude default libraries and specify custom entry point
target_link_options(self_rewrite PRIVATE
        -T${CMAKE_SOURCE_DIR}/no_idata.ld   # Use custom linker script
        -nostdlib                           # Do not link against standard libraries
        -nodefaultlibs                      # Avoid default libraries
        -Wl,-e,mainCRTStartup               # Define custom entry point
        -Wl,--gc-sections                   # Remove unused sections
        -Wl,--no-undefined                  # Ensure no undefined references
        -Wl,--no-insert-timestamp           # Prevent adding timestamp
        -Wl,--strip-all                     # Strip all symbols
        -Wl,-s                              # Remove all symbol table and relocation information
        -Wl,-x                              # Discard all local symbols
        -Wl,--disable-auto-import           # Do not create `.idata`
        -mnop-fun-dllimport
        -O2
        -std=gnu89
)

# Stack handling flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -fno-stack-protector \
    -mno-stack-arg-probe \
    -fno-stack-check"
)

set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -ffreestanding -fno-builtin -O2")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")