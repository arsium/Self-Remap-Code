#pragma once

#define NULL ((void *)0)
//#define FORCEINLINE __attribute__((always_inline))
#define FORCE_INLINE static inline __attribute__((always_inline))
#define NOINLINE __declspec(noinline)

#define far
#define near

#undef FAR
#undef  NEAR
#define FAR                 far
#define NEAR                near
#ifndef CONST
#define CONST               const
#endif


#define RESTRICTED_POINTER

//#define UNALIGNED __unaligned
#define UNALIGNED __attribute__((aligned(1)))

#define _Null_terminated_
#define _NullNull_terminated_
//#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#define DECLSPEC_ALIGN(x)   __attribute__((aligned(x)))

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

#define ANYSIZE_ARRAY 1

//
// For compilers that don't support nameless unions/structs
//
#ifndef DUMMYUNIONNAME
#if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
#define DUMMYUNIONNAME   u
#define DUMMYUNIONNAME2  u2
#define DUMMYUNIONNAME3  u3
#define DUMMYUNIONNAME4  u4
#define DUMMYUNIONNAME5  u5
#define DUMMYUNIONNAME6  u6
#define DUMMYUNIONNAME7  u7
#define DUMMYUNIONNAME8  u8
#define DUMMYUNIONNAME9  u9
#else
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME2
#define DUMMYUNIONNAME3
#define DUMMYUNIONNAME4
#define DUMMYUNIONNAME5
#define DUMMYUNIONNAME6
#define DUMMYUNIONNAME7
#define DUMMYUNIONNAME8
#define DUMMYUNIONNAME9
#endif
#endif // DUMMYUNIONNAME

#ifndef DUMMYSTRUCTNAME
#if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
#define DUMMYSTRUCTNAME  s
#define DUMMYSTRUCTNAME2 s2
#define DUMMYSTRUCTNAME3 s3
#define DUMMYSTRUCTNAME4 s4
#define DUMMYSTRUCTNAME5 s5
#define DUMMYSTRUCTNAME6 s6
#else
#define DUMMYSTRUCTNAME
#define DUMMYSTRUCTNAME2
#define DUMMYSTRUCTNAME3
#define DUMMYSTRUCTNAME4
#define DUMMYSTRUCTNAME5
#define DUMMYSTRUCTNAME6
#endif
#endif // DUMMYSTRUCTNAME

#define NTAPI __stdcall
#define VOID void

#define _Out_
#define _In_opt_z_
#define _Function_class_(x)
#define _In_
#define _In_opt_
#define _Inout_
#define _IRQL_requires_same_ 
#define _Out_opt_
#define _In_reads_bytes_(size)
#define _In_reads_(size)
#define _Out_writes_bytes_to_opt_(size,count)

#if !defined(_W64)
#if !defined(__midl) && (defined(_X86_) || defined(_M_IX86) || defined(_ARM_) || defined(_M_ARM)) && _MSC_VER >= 1300
#define _W64 __w64
#else
#define _W64
#endif
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && !defined(_ARM_) && !defined(_ARM64_) && !defined(_ARM64EC_) && defined(_M_IX86)
#define _X86_
#if !defined(_CHPE_X86_ARM64_) && defined(_M_HYBRID)
#define _CHPE_X86_ARM64_
#endif
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && !defined(_ARM_) && !defined(_ARM64_) && (defined(_M_AMD64) || defined(_M_ARM64EC))
#define _AMD64_
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && !defined(_ARM_) && !defined(_ARM64_) && !defined(_ARM64EC_) && defined(_M_ARM)
#define _ARM_
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && !defined(_ARM_) && !defined(_ARM64_) && !defined(_ARM64EC_) && defined(_M_ARM64)
#define _ARM64_
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_ARM_) && !defined(_ARM64_) && !defined(_ARM64EC_) && defined(_M_ARM64EC)
#define _ARM64EC_
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && !defined(_ARM_) && !defined(_ARM64_) && !defined(_ARM64EC_) && defined(_M_M68K)
#define _68K_
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && !defined(_ARM_) && !defined(_ARM64_) && !defined(_ARM64EC_) && defined(_M_MPPC)
#define _MPPC_
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_M_IX86) && !defined(_AMD64_) && !defined(_ARM_) && !defined(_ARM64_) && !defined(_ARM64EC_) && defined(_M_IA64)
#if !defined(_IA64_)
#define _IA64_
#endif /* !_IA64_ */
#endif


#define PROCESS_PRIORITY_CLASS_UNKNOWN 0
#define PROCESS_PRIORITY_CLASS_IDLE 1
#define PROCESS_PRIORITY_CLASS_NORMAL 2
#define PROCESS_PRIORITY_CLASS_HIGH 3
#define PROCESS_PRIORITY_CLASS_REALTIME 4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL 5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL 6


#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

//structure : RTL_DRIVE_LETTER_CURDIR
#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

//structure : RTL_USER_PROCESS_PARAMETERS
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define RTL_USER_PROC_PROFILE_USER 0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008
#define RTL_USER_PROC_RESERVE_1MB 0x00000020
#define RTL_USER_PROC_RESERVE_16MB 0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000

//typedef procedure : PACTIVATION_CONTEXT_NOTIFY_ROUTINE
#define ACTIVATION_CONTEXT_NOTIFICATION_DESTROY 1
#define ACTIVATION_CONTEXT_NOTIFICATION_ZOMBIFY 2
#define ACTIVATION_CONTEXT_NOTIFICATION_USED 3

//structure : RTL_ACTIVATION_CONTEXT_STACK_FRAME
#define RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_RELEASE_ON_DEACTIVATION 0x00000001
#define RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NO_DEACTIVATE 0x00000002
#define RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ON_FREE_LIST 0x00000004
#define RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_HEAP_ALLOCATED 0x00000008
#define RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NOT_REALLY_ACTIVATED 0x00000010

#define ACTIVATION_CONTEXT_STACK_FLAG_QUERIES_DISABLED 0x00000001

#define GDI_BATCH_BUFFER_SIZE 310

#define STATIC_UNICODE_BUFFER_LENGTH 261
#define WIN32_CLIENT_INFO_LENGTH 62

#define FLS_MAXIMUM_AVAILABLE 4080  
#define TLS_MINIMUM_AVAILABLE 64  

//procedure : NtCreateProcess | NtCreateProcessEx
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS 0x00000800 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000 //
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProcess

// begin_rev
#define THREAD_CREATE_FLAGS_NONE 0x00000000
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
// end_rev


#define IMAGE_DOS_SIGNATURE                                    0x5A4D      //MZ
#define IMAGE_NT_SIGNATURE                                     0x00004550  // PE00

#define IMAGE_SIZEOF_FILE_HEADER                               20
#define IMAGE_SIZEOF_SECTION_HEADER                            40
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES                       16
#define IMAGE_SIZEOF_SHORT_NAME                                8

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC                          0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC                          0x20b

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
#define IMAGE_REL_BASED_RESERVED              6
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
#define IMAGE_REL_BASED_DIR64                 10

//
// Platform-specific based relocation types.
//

#define IMAGE_REL_BASED_IA64_IMM64            9

#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_MIPS_JMPADDR16        9

#define IMAGE_REL_BASED_ARM_MOV32             5
#define IMAGE_REL_BASED_THUMB_MOV32           7

//
// x64 relocations
//
#define IMAGE_REL_AMD64_ABSOLUTE        0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_AMD64_ADDR64          0x0001  // 64-bit address (VA).
#define IMAGE_REL_AMD64_ADDR32          0x0002  // 32-bit address (VA).
#define IMAGE_REL_AMD64_ADDR32NB        0x0003  // 32-bit address w/o image base (RVA).
#define IMAGE_REL_AMD64_REL32           0x0004  // 32-bit relative address from byte following reloc
#define IMAGE_REL_AMD64_REL32_1         0x0005  // 32-bit relative address from byte distance 1 from reloc
#define IMAGE_REL_AMD64_REL32_2         0x0006  // 32-bit relative address from byte distance 2 from reloc
#define IMAGE_REL_AMD64_REL32_3         0x0007  // 32-bit relative address from byte distance 3 from reloc
#define IMAGE_REL_AMD64_REL32_4         0x0008  // 32-bit relative address from byte distance 4 from reloc
#define IMAGE_REL_AMD64_REL32_5         0x0009  // 32-bit relative address from byte distance 5 from reloc
#define IMAGE_REL_AMD64_SECTION         0x000A  // Section index
#define IMAGE_REL_AMD64_SECREL          0x000B  // 32 bit offset from base of section containing target
#define IMAGE_REL_AMD64_SECREL7         0x000C  // 7 bit unsigned offset from base of section containing target
#define IMAGE_REL_AMD64_TOKEN           0x000D  // 32 bit metadata token
#define IMAGE_REL_AMD64_SREL32          0x000E  // 32 bit signed span-dependent value emitted into object
#define IMAGE_REL_AMD64_PAIR            0x000F
#define IMAGE_REL_AMD64_SSPAN32         0x0010  // 32 bit signed span-dependent value applied at link time
#define IMAGE_REL_AMD64_EHANDLER        0x0011
#define IMAGE_REL_AMD64_IMPORT_BR       0x0012  // Indirect branch to an import
#define IMAGE_REL_AMD64_IMPORT_CALL     0x0013  // Indirect call to an import
#define IMAGE_REL_AMD64_CFG_BR          0x0014  // Indirect branch to a CFG check
#define IMAGE_REL_AMD64_CFG_BR_REX      0x0015  // Indirect branch to a CFG check, with REX.W prefix
#define IMAGE_REL_AMD64_CFG_CALL        0x0016  // Indirect call to a CFG check
#define IMAGE_REL_AMD64_INDIR_BR        0x0017  // Indirect branch to a target in RAX (no CFG)
#define IMAGE_REL_AMD64_INDIR_BR_REX    0x0018  // Indirect branch to a target in RAX, with REX.W prefix (no CFG)
#define IMAGE_REL_AMD64_INDIR_CALL      0x0019  // Indirect call to a target in RAX (no CFG)
#define IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_FIRST  0x0020 // Indirect branch for a switch table using Reg 0 (RAX)
#define IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_LAST   0x002F // Indirect branch for a switch table using Reg 15 (R15)

//
// I386 relocation types.
//
#define IMAGE_REL_I386_ABSOLUTE         0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_I386_DIR16            0x0001  // Direct 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_REL16            0x0002  // PC-relative 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32            0x0006  // Direct 32-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32NB          0x0007  // Direct 32-bit reference to the symbols virtual address, base not included
#define IMAGE_REL_I386_SEG12            0x0009  // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
#define IMAGE_REL_I386_SECTION          0x000A
#define IMAGE_REL_I386_SECREL           0x000B
#define IMAGE_REL_I386_TOKEN            0x000C  // clr token
#define IMAGE_REL_I386_SECREL7          0x000D  // 7 bit offset from base of section containing target
#define IMAGE_REL_I386_REL32            0x0014  // PC-relative 32-bit reference to the symbols virtual address

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

//
// TLS Characteristic Flags
//
#define IMAGE_SCN_SCALE_INDEX                0x00000001  // Tls index is scaled

// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG    17

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020  // Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000     // Image should execute in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF     0x4000     // Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

//
// Loader Flags
//
#define IMAGE_LOADER_FLAGS_COMPLUS       0x00000001
#define IMAGE_LOADER_FLAGS_SYSTEM_GLOBAL 0x01000000

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor


#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Aggressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_TARGET_HOST       0x0001  // Useful for indicating we want to interact with the host and not a WoW guest.
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2  // ARM Thumb/Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4  // ARM Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_ARM64             0xAA64  // ARM64 Little-Endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

#define IMAGE_RICH_SIGNATURE 0x52696368
#define IMAGE_DANS_SIGNATURE 0x536E6144

// LDR_DATA_TABLE_ENTRY->Flags
#define LDRP_PACKAGED_BINARY 0x00000001
#define LDRP_MARKED_FOR_REMOVAL 0x00000002
#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_LOAD_NOTIFICATIONS_SENT 0x00000008
#define LDRP_TELEMETRY_ENTRY_PROCESSED 0x00000010
#define LDRP_PROCESS_STATIC_IMPORT 0x00000020
#define LDRP_IN_LEGACY_LISTS 0x00000040
#define LDRP_IN_INDEXES 0x00000080
#define LDRP_SHIM_DLL 0x00000100
#define LDRP_IN_EXCEPTION_TABLE 0x00000200
#define LDRP_LOAD_IN_PROGRESS 0x00001000
#define LDRP_LOAD_CONFIG_PROCESSED 0x00002000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROTECT_DELAY_LOAD 0x00008000
#define LDRP_DONT_CALL_FOR_THREADS 0x00040000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000
#define LDRP_PROCESS_ATTACH_FAILED 0x00100000
#define LDRP_COR_DEFERRED_VALIDATE 0x00200000
#define LDRP_COR_IMAGE 0x00400000
#define LDRP_DONT_RELOCATE 0x00800000
#define LDRP_COR_IL_ONLY 0x01000000
#define LDRP_CHPE_IMAGE 0x02000000
#define LDRP_CHPE_EMULATOR_IMAGE 0x04000000
#define LDRP_REDIRECTED 0x10000000
#define LDRP_COMPAT_DATABASE_PROCESSED 0x80000000

//
// Return the number of elements in a statically sized array.
//   DWORD Buffer[100];
//   RTL_NUMBER_OF(Buffer) == 100
// This is also popularly known as: NUMBER_OF, ARRSIZE, _countof, NELEM, etc.
//
#define RTL_NUMBER_OF_V1(A) (sizeof(A)/sizeof((A)[0]))

#define C __cdecl

#define RtlOffsetToPointer(Base, Offset) ((PCHAR)(((PCHAR)(Base)) + ((ULONG_PTR)(Offset))))
#define RtlPointerToOffset(Base, Pointer) ((ULONG)(((PCHAR)(Pointer)) - ((PCHAR)(Base))))

#define RTL_PTR_ADD(Pointer, Value) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Value)))
#define RTL_PTR_SUBTRACT(Pointer, Value) ((PVOID)((ULONG_PTR)(Pointer) - (ULONG_PTR)(Value)))

#define RTL_MILLISEC_TO_100NANOSEC(m) ((m) * 10000ui64)
#define RTL_SEC_TO_100NANOSEC(s) ((s) * 10000000ui64)
#define RTL_SEC_TO_MILLISEC(s) ((s) * 1000ui64)

#define RTL_MEG (1024UL * 1024UL)
#define RTL_IMAGE_MAX_DOS_HEADER (256UL * RTL_MEG)

#define LDR_DATA_TABLE_ENTRY_SIZE_WINXP FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, DdagNode)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN7 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseNameHashValue)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN8 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, ImplicitPathOptions)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN10 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, SigningLevel)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN11 sizeof(LDR_DATA_TABLE_ENTRY)


// Global flags

#define FLG_STOP_ON_EXCEPTION 0x00000001 // uk
#define FLG_SHOW_LDR_SNAPS 0x00000002 // uk
#define FLG_DEBUG_INITIAL_COMMAND 0x00000004 // k
#define FLG_STOP_ON_HUNG_GUI 0x00000008 // k

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x00000010 // u
#define FLG_HEAP_ENABLE_FREE_CHECK 0x00000020 // u
#define FLG_HEAP_VALIDATE_PARAMETERS 0x00000040 // u
#define FLG_HEAP_VALIDATE_ALL 0x00000080 // u

#define FLG_APPLICATION_VERIFIER 0x00000100 // u
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x00000200 // uk
#define FLG_POOL_ENABLE_TAGGING 0x00000400 // k
#define FLG_HEAP_ENABLE_TAGGING 0x00000800 // u

#define FLG_USER_STACK_TRACE_DB 0x00001000 // u,32
#define FLG_KERNEL_STACK_TRACE_DB 0x00002000 // k,32
#define FLG_MAINTAIN_OBJECT_TYPELIST 0x00004000 // k
#define FLG_HEAP_ENABLE_TAG_BY_DLL 0x00008000 // u

#define FLG_DISABLE_STACK_EXTENSION 0x00010000 // u
#define FLG_ENABLE_CSRDEBUG 0x00020000 // k
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD 0x00040000 // k
#define FLG_DISABLE_PAGE_KERNEL_STACKS 0x00080000 // k

#define FLG_ENABLE_SYSTEM_CRIT_BREAKS 0x00100000 // u
#define FLG_HEAP_DISABLE_COALESCING 0x00200000 // u
#define FLG_ENABLE_CLOSE_EXCEPTIONS 0x00400000 // k
#define FLG_ENABLE_EXCEPTION_LOGGING 0x00800000 // k

#define FLG_ENABLE_HANDLE_TYPE_TAGGING 0x01000000 // k
#define FLG_HEAP_PAGE_ALLOCS 0x02000000 // u
#define FLG_DEBUG_INITIAL_COMMAND_EX 0x04000000 // k
#define FLG_DISABLE_DBGPRINT 0x08000000 // k

#define FLG_CRITSEC_EVENT_CREATION 0x10000000 // u
#define FLG_STOP_ON_UNHANDLED_EXCEPTION 0x20000000 // u,64
#define FLG_LDR_TOP_DOWN                0x20000000   
#define FLG_ENABLE_HANDLE_EXCEPTIONS 0x40000000 // k
#define FLG_DISABLE_PROTDLLS 0x80000000 // u

#define FLG_VALID_BITS 0xfffffdff

#define FLG_USERMODE_VALID_BITS (FLG_STOP_ON_EXCEPTION | \
    FLG_SHOW_LDR_SNAPS | \
    FLG_HEAP_ENABLE_TAIL_CHECK | \
    FLG_HEAP_ENABLE_FREE_CHECK | \
    FLG_HEAP_VALIDATE_PARAMETERS | \
    FLG_HEAP_VALIDATE_ALL | \
    FLG_APPLICATION_VERIFIER | \
    FLG_HEAP_ENABLE_TAGGING | \
    FLG_USER_STACK_TRACE_DB | \
    FLG_HEAP_ENABLE_TAG_BY_DLL | \
    FLG_DISABLE_STACK_EXTENSION | \
    FLG_ENABLE_SYSTEM_CRIT_BREAKS | \
    FLG_HEAP_DISABLE_COALESCING | \
    FLG_DISABLE_PROTDLLS | \
    FLG_HEAP_PAGE_ALLOCS | \
    FLG_CRITSEC_EVENT_CREATION | \
    FLG_LDR_TOP_DOWN)

#define FLG_BOOTONLY_VALID_BITS (FLG_KERNEL_STACK_TRACE_DB | \
    FLG_MAINTAIN_OBJECT_TYPELIST | \
    FLG_ENABLE_CSRDEBUG | \
    FLG_DEBUG_INITIAL_COMMAND | \
    FLG_DEBUG_INITIAL_COMMAND_EX | \
    FLG_DISABLE_PAGE_KERNEL_STACKS)

#define FLG_KERNELMODE_VALID_BITS (FLG_STOP_ON_EXCEPTION | \
    FLG_SHOW_LDR_SNAPS | \
    FLG_STOP_ON_HUNG_GUI | \
    FLG_POOL_ENABLE_TAGGING | \
    FLG_ENABLE_KDEBUG_SYMBOL_LOAD | \
    FLG_ENABLE_CLOSE_EXCEPTIONS | \
    FLG_ENABLE_EXCEPTION_LOGGING | \
    FLG_ENABLE_HANDLE_TYPE_TAGGING | \
    FLG_DISABLE_DBGPRINT | \
    FLG_ENABLE_HANDLE_EXCEPTIONS)

#define DECLSPEC_IMPORT __declspec(dllimport)
#define NTSYSAPI     DECLSPEC_IMPORT
#define NTSYSCALLAPI DECLSPEC_IMPORT


#define OBJ_PROTECT_CLOSE                   0x00000001L
#define OBJ_INHERIT                         0x00000002L
#define OBJ_AUDIT_OBJECT_CLOSE              0x00000004L
#define OBJ_NO_RIGHTS_UPGRADE               0x00000008L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) { sizeof(OBJECT_ATTRIBUTES), NULL, n, a, NULL, NULL }
#define RTL_INIT_OBJECT_ATTRIBUTES(n, a) RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)

#define OBJ_NAME_PATH_SEPARATOR ((WCHAR)L'\\')
#define OBJ_NAME_ALTPATH_SEPARATOR ((WCHAR)L'/')

// Protection constants

#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD 0x100
#define PAGE_NOCACHE 0x200
#define PAGE_WRITECOMBINE 0x400

#define PAGE_REVERT_TO_FILE_MAP     0x80000000
#define PAGE_ENCLAVE_THREAD_CONTROL 0x80000000
#define PAGE_TARGETS_NO_UPDATE      0x40000000
#define PAGE_TARGETS_INVALID        0x40000000
#define PAGE_ENCLAVE_UNVALIDATED    0x20000000
#define PAGE_ENCLAVE_NO_CHANGE      0x20000000
#define PAGE_ENCLAVE_MASK           0x10000000
#define PAGE_ENCLAVE_DECOMMIT       (PAGE_ENCLAVE_MASK | 0)
#define PAGE_ENCLAVE_SS_FIRST       (PAGE_ENCLAVE_MASK | 1)
#define PAGE_ENCLAVE_SS_REST        (PAGE_ENCLAVE_MASK | 2)

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_DECOMMIT 0x00004000
#define MEM_RELEASE 0x00008000
#define MEM_FREE 0x00010000
#define MEM_PRIVATE 0x00020000
#define MEM_MAPPED 0x00040000
#define MEM_RESET 0x00080000
#define MEM_TOP_DOWN 0x00100000
#define MEM_WRITE_WATCH 0x00200000
#define MEM_PHYSICAL 0x00400000
#define MEM_ROTATE 0x00800000
#define MEM_DIFFERENT_IMAGE_BASE_OK 0x00800000
#define MEM_RESET_UNDO 0x01000000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_DOS_LIM 0x40000000
#define MEM_4MB_PAGES 0x80000000
#define MEM_64K_PAGES (MEM_LARGE_PAGES | MEM_PHYSICAL)

#define MEM_UNMAP_WITH_TRANSIENT_BOOST 0x00000001
#define MEM_COALESCE_PLACEHOLDERS 0x00000001
#define MEM_PRESERVE_PLACEHOLDER 0x00000002
#define MEM_REPLACE_PLACEHOLDER 0x00004000
#define MEM_RESERVE_PLACEHOLDER 0x00040000

#define SEC_HUGE_PAGES 0x00020000
#define SEC_PARTITION_OWNER_HANDLE 0x00040000
#define SEC_64K_PAGES 0x00080000
#define SEC_DRIVER_IMAGE 0x00100000 // rev
#define SEC_BASED 0x00200000
#define SEC_NO_CHANGE 0x00400000
#define SEC_FILE 0x00800000
#define SEC_IMAGE 0x01000000
#define SEC_PROTECTED_IMAGE 0x02000000
#define SEC_RESERVE 0x04000000
#define SEC_COMMIT 0x08000000
#define SEC_NOCACHE 0x10000000
#define SEC_GLOBAL 0x20000000
#define SEC_WRITECOMBINE 0x40000000
#define SEC_LARGE_PAGES 0x80000000
#define SEC_IMAGE_NO_EXECUTE (SEC_IMAGE | SEC_NOCACHE)

// private
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.

// begin_rev

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_OBJECT \
    PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER \
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION \
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHPE \
    PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS \
    PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE \
    PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_COMPONENT_FILTER \
    PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES \
    PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE)

// begin_wdm
//
//  The following are masks for the predefined standard access types
//

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)

//
// AccessSystemAcl access type
//

#define ACCESS_SYSTEM_SECURITY           (0x01000000L)

//
// MaximumAllowed access type
//

#define MAXIMUM_ALLOWED                  (0x02000000L)

//
//  These are the generic rights.
//

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  
//

#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)


//
#define THREAD_TERMINATE                 (0x0001)  
#define THREAD_SUSPEND_RESUME            (0x0002)  
#define THREAD_GET_CONTEXT               (0x0008)  
#define THREAD_SET_CONTEXT               (0x0010)  
#define THREAD_QUERY_INFORMATION         (0x0040)  
#define THREAD_SET_INFORMATION           (0x0020)  
#define THREAD_SET_THREAD_TOKEN          (0x0080)
#define THREAD_IMPERSONATE               (0x0100)
#define THREAD_DIRECT_IMPERSONATION      (0x0200)
#define THREAD_SET_LIMITED_INFORMATION   (0x0400)  // winnt
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)  // winnt
#define THREAD_RESUME                    (0x1000)  // winnt

#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

//
// Job Object Specific Access Rights
//

#define JOB_OBJECT_ASSIGN_PROCESS           (0x0001)
#define JOB_OBJECT_SET_ATTRIBUTES           (0x0002)
#define JOB_OBJECT_QUERY                    (0x0004)
#define JOB_OBJECT_TERMINATE                (0x0008)
#define JOB_OBJECT_SET_SECURITY_ATTRIBUTES  (0x0010)
#define JOB_OBJECT_IMPERSONATE              (0x0020)
#define JOB_OBJECT_ALL_ACCESS       (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                        0x3F )

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE 0x1

#define STATUS_PORT_NOT_SET              ((NTSTATUS)0xC0000353L)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_FATAL_APP_EXIT            ((NTSTATUS)0x40000015L)    // winnt
//
// MessageId: STATUS_NOT_ALL_ASSIGNED
//
// MessageText:
//
// Indicates not all privileges or groups referenced are assigned to the caller.
// This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned.
//
#define STATUS_NOT_ALL_ASSIGNED          ((NTSTATUS)0x00000106L)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)

#define NT_CUSTOMER_SHIFT 29
#define NT_CUSTOMER(Status) ((((ULONG)(Status)) >> NT_CUSTOMER_SHIFT) & 1)

#define NT_FACILITY_MASK 0xfff
#define NT_FACILITY_SHIFT 16
#define NT_FACILITY(Status) ((((ULONG)(Status)) >> NT_FACILITY_SHIFT) & NT_FACILITY_MASK)

#define NT_NTWIN32(Status) (NT_FACILITY(Status) == FACILITY_NTWIN32)
#define WIN32_FROM_NTSTATUS(Status) (((ULONG)(Status)) & 0xffff)

#define EXCEPTION_NONCONTINUABLE 0x1        // Noncontinuable exception
#define EXCEPTION_UNWINDING 0x2             // Unwind is in progress
#define EXCEPTION_EXIT_UNWIND 0x4           // Exit unwind is in progress
#define EXCEPTION_STACK_INVALID 0x8         // Stack out of limits or unaligned
#define EXCEPTION_NESTED_CALL 0x10          // Nested exception handler call
#define EXCEPTION_TARGET_UNWIND 0x20        // Target unwind in progress
#define EXCEPTION_COLLIDED_UNWIND 0x40      // Collided exception handler call
#define EXCEPTION_SOFTWARE_ORIGINATE 0x80   // Exception originated in software

#define EXCEPTION_UNWIND (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | \
                          EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)

#define IS_UNWINDING(Flag) ((Flag & EXCEPTION_UNWIND) != 0)
#define IS_DISPATCHING(Flag) ((Flag & EXCEPTION_UNWIND) == 0)
#define IS_TARGET_UNWIND(Flag) (Flag & EXCEPTION_TARGET_UNWIND)

#define EXCEPTION_MAXIMUM_PARAMETERS 15 // maximum number of exception parameters

#define STATUS_TOO_MANY_SECRETS 0xC0000156
#define STATUS_SECRET_TOO_LONG 0xC0000157

#define STDAPICALLTYPE          __stdcall
#define STDAPIVCALLTYPE         __cdecl

#define DBG_STATUS_CONTROL_C 1
#define DBG_STATUS_SYSRQ 2
#define DBG_STATUS_BUGCHECK_FIRST 3
#define DBG_STATUS_BUGCHECK_SECOND 4
#define DBG_STATUS_FATAL 5
#define DBG_STATUS_DEBUG_CONTROL 6
#define DBG_STATUS_WORKER 7

#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_CONTINUE_EXECUTION -1

#define PROCESSOR_FEATURE_MAX 64

#define XSTATE_LEGACY_FLOATING_POINT        (0)
#define XSTATE_LEGACY_SSE                   (1)
#define XSTATE_GSSE                         (2)
#define XSTATE_AVX                          (XSTATE_GSSE)
#define XSTATE_MPX_BNDREGS                  (3)
#define XSTATE_MPX_BNDCSR                   (4)
#define XSTATE_AVX512_KMASK                 (5)
#define XSTATE_AVX512_ZMM_H                 (6)
#define XSTATE_AVX512_ZMM                   (7)
#define XSTATE_IPT                          (8)
#define XSTATE_PASID                        (10)
#define XSTATE_CET_U                        (11)
#define XSTATE_CET_S                        (12)
#define XSTATE_AMX_TILE_CONFIG              (17)
#define XSTATE_AMX_TILE_DATA                (18)
#define XSTATE_LWP                          (62)
#define MAXIMUM_XSTATE_FEATURES             (64)

//
// Known extended CPU state feature MASKs
//

#define XSTATE_MASK_LEGACY_FLOATING_POINT   (1ui64 << (XSTATE_LEGACY_FLOATING_POINT))
#define XSTATE_MASK_LEGACY_SSE              (1ui64 << (XSTATE_LEGACY_SSE))
#define XSTATE_MASK_LEGACY                  (XSTATE_MASK_LEGACY_FLOATING_POINT | \
                                             XSTATE_MASK_LEGACY_SSE)

#define XSTATE_MASK_GSSE                    (1ui64 << (XSTATE_GSSE))
#define XSTATE_MASK_AVX                     (XSTATE_MASK_GSSE)
#define XSTATE_MASK_MPX                     ((1ui64 << (XSTATE_MPX_BNDREGS)) | \
                                             (1ui64 << (XSTATE_MPX_BNDCSR)))

#define XSTATE_MASK_AVX512                  ((1ui64 << (XSTATE_AVX512_KMASK)) | \
                                             (1ui64 << (XSTATE_AVX512_ZMM_H)) | \
                                             (1ui64 << (XSTATE_AVX512_ZMM)))

#define XSTATE_MASK_IPT                     (1ui64 << (XSTATE_IPT))
#define XSTATE_MASK_PASID                   (1ui64 << (XSTATE_PASID))
#define XSTATE_MASK_CET_U                   (1ui64 << (XSTATE_CET_U))
#define XSTATE_MASK_CET_S                   (1ui64 << (XSTATE_CET_S))
#define XSTATE_MASK_AMX_TILE_CONFIG         (1ui64 << (XSTATE_AMX_TILE_CONFIG))
#define XSTATE_MASK_AMX_TILE_DATA           (1ui64 << (XSTATE_AMX_TILE_DATA))
#define XSTATE_MASK_LWP                     (1ui64 << (XSTATE_LWP))

#if defined(_AMD64_)

#define XSTATE_MASK_ALLOWED                 (XSTATE_MASK_LEGACY | \
                                             XSTATE_MASK_AVX | \
                                             XSTATE_MASK_MPX | \
                                             XSTATE_MASK_AVX512 | \
                                             XSTATE_MASK_IPT | \
                                             XSTATE_MASK_PASID | \
                                             XSTATE_MASK_CET_U | \
                                             XSTATE_MASK_AMX_TILE_CONFIG | \
                                             XSTATE_MASK_AMX_TILE_DATA | \
                                             XSTATE_MASK_LWP)

#elif defined(_X86_)

#define XSTATE_MASK_ALLOWED                 (XSTATE_MASK_LEGACY | \
                                             XSTATE_MASK_AVX | \
                                             XSTATE_MASK_MPX | \
                                             XSTATE_MASK_AVX512 | \
                                             XSTATE_MASK_IPT | \
                                             XSTATE_MASK_CET_U | \
                                             XSTATE_MASK_LWP)

#endif

#define XSTATE_MASK_PERSISTENT              ((1ui64 << (XSTATE_MPX_BNDCSR)) | \
                                             XSTATE_MASK_LWP)

#define XSTATE_MASK_USER_VISIBLE_SUPERVISOR (XSTATE_MASK_CET_U)

#define XSTATE_MASK_LARGE_FEATURES          (XSTATE_MASK_AMX_TILE_DATA)

#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7ffe0000)
//USER_SHARED_DATA->TickCountQuad

#define HARDERROR_OVERRIDE_ERRORMODE 0x10000000

#define RTL_ACQUIRE_PRIVILEGE_REVERT 0x00000001
#define RTL_ACQUIRE_PRIVILEGE_PROCESS 0x00000002

#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)

#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE (36L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE

#define SE_PRIVILEGE_ENABLED_BY_DEFAULT (0x00000001L)
#define SE_PRIVILEGE_ENABLED            (0x00000002L)
#define SE_PRIVILEGE_REMOVED            (0X00000004L)
#define SE_PRIVILEGE_USED_FOR_ACCESS    (0x80000000L)

#define SE_PRIVILEGE_VALID_ATTRIBUTES   (SE_PRIVILEGE_ENABLED_BY_DEFAULT | \
                                         SE_PRIVILEGE_ENABLED            | \
                                         SE_PRIVILEGE_REMOVED            | \
                                         SE_PRIVILEGE_USED_FOR_ACCESS)

#define DISABLE_MAX_PRIVILEGE   0x1 
#define SANDBOX_INERT           0x2 
#define LUA_TOKEN               0x4 
#define WRITE_RESTRICTED        0x8 

#define OWNER_SECURITY_INFORMATION                  (0x00000001L)
#define GROUP_SECURITY_INFORMATION                  (0x00000002L)
#define DACL_SECURITY_INFORMATION                   (0x00000004L)
#define SACL_SECURITY_INFORMATION                   (0x00000008L)
#define LABEL_SECURITY_INFORMATION                  (0x00000010L)
#define ATTRIBUTE_SECURITY_INFORMATION              (0x00000020L)
#define SCOPE_SECURITY_INFORMATION                  (0x00000040L)
#define PROCESS_TRUST_LABEL_SECURITY_INFORMATION    (0x00000080L)
#define ACCESS_FILTER_SECURITY_INFORMATION          (0x00000100L)
#define BACKUP_SECURITY_INFORMATION                 (0x00010000L)

#define PROTECTED_DACL_SECURITY_INFORMATION         (0x80000000L)
#define PROTECTED_SACL_SECURITY_INFORMATION         (0x40000000L)
#define UNPROTECTED_DACL_SECURITY_INFORMATION       (0x20000000L)
#define UNPROTECTED_SACL_SECURITY_INFORMATION       (0x10000000L)

//
// Token Specific Access Rights.
//

#define TOKEN_ASSIGN_PRIMARY    (0x0001)
#define TOKEN_DUPLICATE         (0x0002)//2
#define TOKEN_IMPERSONATE       (0x0004)//4
#define TOKEN_QUERY             (0x0008)//8
#define TOKEN_QUERY_SOURCE      (0x0010)//16
#define TOKEN_ADJUST_PRIVILEGES (0x0020)//32
#define TOKEN_ADJUST_GROUPS     (0x0040)//64
#define TOKEN_ADJUST_DEFAULT    (0x0080)//128
#define TOKEN_ADJUST_SESSIONID  (0x0100)//256

#define TOKEN_ALL_ACCESS_P (STANDARD_RIGHTS_REQUIRED  |\
                          TOKEN_ASSIGN_PRIMARY      |\
                          TOKEN_DUPLICATE           |\
                          TOKEN_IMPERSONATE         |\
                          TOKEN_QUERY               |\
                          TOKEN_QUERY_SOURCE        |\
                          TOKEN_ADJUST_PRIVILEGES   |\
                          TOKEN_ADJUST_GROUPS       |\
                          TOKEN_ADJUST_DEFAULT )

#if ((defined(_WIN32_WINNT) && (_WIN32_WINNT > 0x0400)) || (!defined(_WIN32_WINNT)))
#define TOKEN_ALL_ACCESS  (TOKEN_ALL_ACCESS_P |\
                          TOKEN_ADJUST_SESSIONID )
#else
#define TOKEN_ALL_ACCESS  (TOKEN_ALL_ACCESS_P)
#endif

#define TOKEN_READ       (STANDARD_RIGHTS_READ      |\
                          TOKEN_QUERY)


#define TOKEN_WRITE      (STANDARD_RIGHTS_WRITE     |\
                          TOKEN_ADJUST_PRIVILEGES   |\
                          TOKEN_ADJUST_GROUPS       |\
                          TOKEN_ADJUST_DEFAULT)

#define TOKEN_EXECUTE    (STANDARD_RIGHTS_EXECUTE)

#define TOKEN_TRUST_CONSTRAINT_MASK    (STANDARD_RIGHTS_READ  | \
                                       TOKEN_QUERY  |\
                                       TOKEN_QUERY_SOURCE )

#define TOKEN_TRUST_ALLOWED_MASK    (TOKEN_TRUST_CONSTRAINT_MASK |\
                                    TOKEN_DUPLICATE              |\
                                    TOKEN_IMPERSONATE)

#if (NTDDI_VERSION >= NTDDI_WIN8)

#define TOKEN_ACCESS_PSEUDO_HANDLE_WIN8 (TOKEN_QUERY | TOKEN_QUERY_SOURCE)

#define TOKEN_ACCESS_PSEUDO_HANDLE TOKEN_ACCESS_PSEUDO_HANDLE_WIN8

#endif

#define SECURITY_DYNAMIC_TRACKING      (TRUE)
#define SECURITY_STATIC_TRACKING       (FALSE)

#define HEAP_NO_SERIALIZE               0x00000001      
#define HEAP_GROWABLE                   0x00000002      
#define HEAP_GENERATE_EXCEPTIONS        0x00000004      
#define HEAP_ZERO_MEMORY                0x00000008      
#define HEAP_REALLOC_IN_PLACE_ONLY      0x00000010      
#define HEAP_TAIL_CHECKING_ENABLED      0x00000020      
#define HEAP_FREE_CHECKING_ENABLED      0x00000040      
#define HEAP_DISABLE_COALESCE_ON_FREE   0x00000080      
#define HEAP_CREATE_ALIGN_16            0x00010000      
#define HEAP_CREATE_ENABLE_TRACING      0x00020000      
#define HEAP_CREATE_ENABLE_EXECUTE      0x00040000      
#define HEAP_MAXIMUM_TAG                0x0FFF              
#define HEAP_PSEUDO_TAG_FLAG            0x8000              
#define HEAP_TAG_SHIFT                  18                  
#define HEAP_CREATE_SEGMENT_HEAP        0x00000100      
#define HEAP_CREATE_HARDENED            0x00000200

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

// begin_rev
#define PS_STD_INPUT_HANDLE 0x1
#define PS_STD_OUTPUT_HANDLE 0x2
#define PS_STD_ERROR_HANDLE 0x4
// end_rev

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ui64 << 44)

#ifndef DECLSPEC_NOINITALL
#if (_MSC_VER >= 1915) && !defined(MIDL_PASS) && !defined(SORTPP_PASS) && !defined(RC_INVOKED)
#define DECLSPEC_NOINITALL __pragma(warning(push)) __pragma(warning(disable:4845)) __declspec(no_init_all) __pragma(warning(pop))
#else
#define DECLSPEC_NOINITALL
#endif
#endif

#define HEAP_SKIP_VALIDATION_CHECKS         0x10000000
#define HEAP_VALIDATE_PARAMETERS_ENABLED    0x40000000