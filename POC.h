#pragma once
#include "HostileHeader.h"
#define PE_HEADERS_SIZE_MEM 0x1000

typedef struct _section_spec
{
    HANDLE handle;
    ULONG_PTR base;
    SIZE_T size;
}section_spec, * p_section_spec;

PULARGE_INTEGER find_current_section_of_function(PULARGE_INTEGER, ULONG_PTR);
HANDLE alloc_space(SIZE_T);
PVOID map_loc(HANDLE, PVOID, SIZE_T, SIZE_T, DWORD, DWORD);
void unmap_loc(PVOID);
void copy_headers_and_section_mapped(PVOID, PVOID);
void close_handle(HANDLE);
VOID setup(VOID);
VOID mapper(section_spec, section_spec, section_spec);
typedef void local_mapper(section_spec, section_spec, section_spec); typedef local_mapper *p_local_mapper;

FORCE_INLINE VOID mem_copy(VOID* src, VOID* dst, SIZE_T size)
{
    SIZE_T i = 0;
    CHAR* src_char = (CHAR*)src;
    CHAR* dst_char = (CHAR*)dst;
    while(i < size)
    {
        dst_char[i] = src_char[i];
        i++;
    }
}

FORCE_INLINE LPVOID get_procedure_address_nt(char* function_name)
{
    DWORD_PTR module_address = (DWORD_PTR)GetModuleBaseAddress(L"ntdll.dll\0");
    IMAGE_DOS_HEADER* p_dos_header = (IMAGE_DOS_HEADER*)module_address;
    IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*)(module_address + p_dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER* p_optional_header = &p_nt_header->OptionalHeader;
    IMAGE_DATA_DIRECTORY* p_export_data_directory = (IMAGE_DATA_DIRECTORY*)(&p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* p_export_data_header = (IMAGE_EXPORT_DIRECTORY*)(module_address + p_export_data_directory->VirtualAddress);

    DWORD* p_export_address_table = (DWORD*)(module_address + p_export_data_header->AddressOfFunctions);
    DWORD* p_function_name_table = (DWORD*)(module_address + p_export_data_header->AddressOfNames);
    WORD* p_ordinal_name_table = (WORD*)(module_address + p_export_data_header->AddressOfNameOrdinals);

    for (DWORD i = 0; i < p_export_data_header->NumberOfNames; i++)
    {
        char* current_function_name = (char*)(module_address + (DWORD_PTR)p_function_name_table[i]);

        if (CompareAnsi(function_name, current_function_name) == TRUE)
        {
            return (LPVOID)(module_address + (DWORD_PTR)p_export_address_table[p_ordinal_name_table[i]]);
        }
    }
    return NULL;
}

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    ); typedef NtCreateSection * PNtCreateSection ;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    ); typedef NtMapViewOfSection *PNtMapViewOfSection;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    );typedef NtUnmapViewOfSection *PNtUnmapViewOfSection;

typedef NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose(
    _In_ HANDLE Handle
    );typedef NtClose *PNtClose;

#define SECTION_QUERY       0x0001
#define SECTION_MAP_WRITE   0x0002
#define SECTION_MAP_READ    0x0004
#define SECTION_MAP_EXECUTE 0x0008
#define SECTION_EXTEND_SIZE 0x0010
#define SECTION_READ_EXEC_WRITE (SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE)
#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
SECTION_MAP_WRITE |      \
SECTION_MAP_READ |       \
SECTION_MAP_EXECUTE |    \
SECTION_EXTEND_SIZE)


#define GET_PROTECTION(executable, readable, writable) \
((executable) ? \
((readable) ? \
((writable) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) : \
((writable) ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE)) : \
((readable) ? \
((writable) ? PAGE_READWRITE : PAGE_READONLY) : \
((writable) ? PAGE_WRITECOPY : PAGE_NOACCESS)))

#define ConvertSectionCharacteristicsToPageProtection(Characteristics) \
GET_PROTECTION( \
((Characteristics) & IMAGE_SCN_MEM_EXECUTE) != 0, \
((Characteristics) & IMAGE_SCN_MEM_READ) != 0, \
((Characteristics) & IMAGE_SCN_MEM_WRITE) != 0) | \
(((Characteristics) & IMAGE_SCN_MEM_NOT_CACHED) ? PAGE_NOCACHE : 0)
