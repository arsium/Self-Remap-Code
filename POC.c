
#include "POC.h"

__attribute__((section(".text")))

PULARGE_INTEGER find_current_section_of_function(PULARGE_INTEGER off, ULONG_PTR current_function)
{
    PPEB p_peb = NtCurrentPeb();
    IMAGE_DOS_HEADER* p_dos_hrd = p_peb->ImageBaseAddress;
    PIMAGE_NT_HEADERS p_nt_hdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)p_dos_hrd + p_dos_hrd->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(p_nt_hdr);

    for (WORD i = 0; i < p_nt_hdr->FileHeader.NumberOfSections; i++, section++)
    {
        ULONG_PTR start_of_section = (ULONG_PTR)(p_dos_hrd) +  section->VirtualAddress;
        ULONG_PTR end_of_section = (ULONG_PTR)(p_dos_hrd) +  section->VirtualAddress +  section->Misc.VirtualSize;
        if(current_function >= start_of_section && current_function <= end_of_section)
        {
            off->s.HighPart = section->VirtualAddress;
            off->s.LowPart = section->Misc.VirtualSize;
        }
    }
    return off;
}

HANDLE alloc_space(SIZE_T size)
{
    PNtCreateSection p_nt_create_section = get_procedure_address_nt("NtCreateSection\0");
    HANDLE h_section = NULL;
    LARGE_INTEGER size_loc;
    size_loc.QuadPart = (LONGLONG)size;
    (void)p_nt_create_section(&h_section, SECTION_ALL_ACCESS, nullptr,
        &size_loc, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    return h_section;
}

PVOID map_loc(HANDLE handle ,PVOID add, SIZE_T size, SIZE_T offset, DWORD alloc_flag, DWORD protect_flag)
{
    PNtMapViewOfSection p_map_view_of_section = get_procedure_address_nt("NtMapViewOfSection\0");
    SIZE_T size_loc = size;
    PVOID local_view = (PVOID)add;
    LARGE_INTEGER local_off;
    local_off.QuadPart = (LONGLONG)offset;
    (void)p_map_view_of_section(handle,
       NtCurrentProcess(), &local_view, 0, size_loc, &local_off,
       &size_loc, ViewUnmap, alloc_flag, protect_flag);
    return local_view;
}

void unmap_loc(PVOID add)
{
    PNtUnmapViewOfSection p_nt_unmap_view_of_section = get_procedure_address_nt("NtUnmapViewOfSection\0");
    (void)p_nt_unmap_view_of_section(NtCurrentProcess(), add);
}

void copy_headers_and_section_mapped(PVOID src, PVOID dst)
{
///Copy headers
    mem_copy(src,  dst,  PE_HEADERS_SIZE_MEM);
    IMAGE_DOS_HEADER* p_dos_hrd = (IMAGE_DOS_HEADER*)src;
    PIMAGE_NT_HEADERS p_nt_hdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)p_dos_hrd + p_dos_hrd->e_lfanew);
    PIMAGE_SECTION_HEADER p_section = IMAGE_FIRST_SECTION(p_nt_hdr);

///Copy all sections
    for (WORD i = 0; i < p_nt_hdr->FileHeader.NumberOfSections; i++, p_section++)
    {
        mem_copy(src + p_section->VirtualAddress,  dst +  p_section->VirtualAddress,  p_section->Misc.VirtualSize);
    }
}

void close_handle(HANDLE h)
{
    PNtClose p_nt_close = get_procedure_address_nt("NtClose\0");
    (void)p_nt_close(h);
}

void setup(VOID)
{
    section_spec remote_mapper;
    section_spec local_pe_copy;
    section_spec original_section;
///HIGH part : virtual address of section / LOW part : virtual size of section
    ULARGE_INTEGER va_and_size;
    (VOID)find_current_section_of_function(&va_and_size, (ULONG_PTR)&mapper);
    original_section.size = (SIZE_T)va_and_size.s.LowPart;
    original_section.handle = NULL;
///Create space for mapper
    remote_mapper.size = (SIZE_T)va_and_size.s.LowPart;
    remote_mapper.handle  = alloc_space(remote_mapper.size);
///Map section for mapper read+write
///NO SEC COMMIT HERE : won't work
    remote_mapper.base = (ULONG_PTR)map_loc(remote_mapper.handle, NULL, remote_mapper.size, 0, SEC_NO_CHANGE, PAGE_READWRITE);
///Copy function code
    PPEB p_peb = (PPEB)NtCurrentPeb();
    original_section.base = (ULONG_PTR)p_peb->ImageBaseAddress;
///Only copy .text section or the section of function "mapper", rest not needed (think like shellcode)
    mem_copy(p_peb->ImageBaseAddress + va_and_size.s.HighPart, (PVOID)remote_mapper.base,  va_and_size.s.LowPart);

///Unmap to remap with r+x
    unmap_loc((PVOID)remote_mapper.base);
///Remap now with read+execute to same address for mapper
    remote_mapper.base = (ULONG_PTR)map_loc(remote_mapper.handle, (PVOID)remote_mapper.base, remote_mapper.size, 0, SEC_NO_CHANGE, PAGE_EXECUTE_READ);

///Setup second section with full PE copied from mapped address
    IMAGE_DOS_HEADER* p_dos_hdr = (IMAGE_DOS_HEADER*)p_peb->ImageBaseAddress;
    PIMAGE_NT_HEADERS p_nt_hdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)p_dos_hdr + p_dos_hdr->e_lfanew);
    local_pe_copy.size = (SIZE_T)p_nt_hdr->OptionalHeader.SizeOfImage;
    local_pe_copy.handle = alloc_space(local_pe_copy.size);
///Map second section with full PE mapped
    local_pe_copy.base = (ULONG_PTR)map_loc(local_pe_copy.handle, NULL, local_pe_copy.size, 0, SEC_NO_CHANGE, PAGE_READWRITE);
///Copy full PE to this new section ----- ERROR HERE ON MemCopy : granularity : .text section separated from header : two block of 64kb
    copy_headers_and_section_mapped(p_peb->ImageBaseAddress,  (VOID*)local_pe_copy.base);
///Now, execute mapper to remap to base exec
///Don't forget to minus the virtual address of the section so we have (&mapper - base_address - virtual address) + remote_mapper.base : should be correct
    PVOID mapper_address = (PVOID)((ULONG_PTR)&mapper - (ULONG_PTR)p_peb->ImageBaseAddress - va_and_size.s.HighPart + remote_mapper.base);
    p_local_mapper p_mapper = mapper_address;

///Come back to normal base address, clean the r+x section of "mapper", then clean section r+w with PE fully copied
    p_mapper(remote_mapper, local_pe_copy, original_section);
    unmap_loc((PVOID)local_pe_copy.base);
    unmap_loc((PVOID)remote_mapper.base);
    close_handle(local_pe_copy.handle);
    close_handle(remote_mapper.handle);
}

void mapper(section_spec current_section, section_spec read_write_pe,  section_spec original_section)
{
///Get what we need to remap before unmapping whole PE
    PNtUnmapViewOfSection p_nt_unmap_view_of_section = get_procedure_address_nt("NtUnmapViewOfSection\0");
    PNtMapViewOfSection p_map_view_of_section = get_procedure_address_nt("NtMapViewOfSection\0");
    PPEB p_peb = NtCurrentPeb();

///Unmap executable
    unmap_loc(p_peb->ImageBaseAddress);

///Read headers from copy
    IMAGE_DOS_HEADER* p_dos_hrd = (IMAGE_DOS_HEADER*)read_write_pe.base;
    PIMAGE_NT_HEADERS p_nt_hdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)p_dos_hrd + p_dos_hrd->e_lfanew);
    PIMAGE_SECTION_HEADER p_section = IMAGE_FIRST_SECTION(p_nt_hdr);

    SIZE_T size_loc = PE_HEADERS_SIZE_MEM;
    PVOID local_view = (PVOID)p_peb->ImageBaseAddress;
    LARGE_INTEGER local_off;
    local_off.QuadPart = (LONGLONG)0;

///Remap the headers to base address
    (void)p_map_view_of_section(read_write_pe.handle,
       NtCurrentProcess(), &local_view, 0, size_loc, &local_off,
       &size_loc, ViewUnmap, SEC_NO_CHANGE, PAGE_READWRITE);

    p_dos_hrd = (IMAGE_DOS_HEADER*)local_view;
///Just random value to test
    p_dos_hrd->e_magic = 0xADDE;
    (void)p_nt_unmap_view_of_section(NtCurrentProcess(), local_view);

    (void)p_map_view_of_section(read_write_pe.handle,
   NtCurrentProcess(), &local_view, 0, size_loc, &local_off,
   &size_loc, ViewUnmap, SEC_NO_CHANGE,  PAGE_READONLY | PAGE_GUARD);//

    local_view = nullptr;
    local_off.QuadPart = 0;
    ULONG protect_flag = 0;

///Remap all sections
    for (WORD i = 0; i < p_nt_hdr->FileHeader.NumberOfSections; i++, p_section++)
    {
        protect_flag = ConvertSectionCharacteristicsToPageProtection(p_section->Characteristics);
        size_loc = p_section->Misc.VirtualSize;
        local_view = (PVOID)(ULONG_PTR)p_peb->ImageBaseAddress + p_section->VirtualAddress;
        local_off.QuadPart = (LONGLONG)p_section->VirtualAddress;
        (void)p_map_view_of_section(read_write_pe.handle, NtCurrentProcess(), &local_view, 0, size_loc, &local_off, &size_loc, ViewUnmap, SEC_NO_CHANGE, protect_flag | PAGE_NOCACHE);
    }
}