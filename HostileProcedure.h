#pragma once
#include "HostileHeader.h"


#if defined(_WIN64)
#pragma intrinsic(__readgsqword)
#else
#pragma intrinsic(__readfsdword)
#endif


FORCE_INLINE size_t _wcslen(const WCHAR* str)
{
    volatile const WCHAR* p = str;
    while (*p != L'\0') {
        p++;
    }
    return (size_t)(p - str);
}


FORCE_INLINE size_t _strlen(const char* str) {
    volatile const CHAR* ptr = str;
    while (*ptr != '\0') {
        ptr++;
    }
    return ptr - str;
}

FORCE_INLINE INT StringLengthA(char* str)
{
    int length;
    for (length = 0; str[length] != '\0'; length++) {}
    return length;
}

FORCE_INLINE INT StringLengthW(WCHAR* str) {
    int length;
    for (length = 0; str[length] != L'\0'; length++) {}
    return length;
}

FORCE_INLINE WCHAR ToLowerW(WCHAR ch)
{
    if (ch > 0x40 && ch < 0x5B)
    {
        return ch + 0x20;
    }
    return ch;
}

FORCE_INLINE char ToLowerA(char ch)
{
    if (ch > 96 && ch < 123)
    {
        ch -= 32;
    }
    return ch;
}


FORCE_INLINE BOOLEAN C CompareUnicode(PWSTR u1, PWSTR u2)
{
    for (int i = 0; i < StringLengthW(u1); i++)
    {
        if (ToLowerW(u1[i]) != ToLowerW(u2[i]))
            return FALSE;
    }
    return TRUE;
}

FORCE_INLINE BOOLEAN CompareAnsi(char* u1, char* u2)
{
    for (int i = 0; i < StringLengthA(u1); i++)
    {
        if (ToLowerA(u1[i]) != ToLowerA(u2[i]))
            return FALSE;
    }
    return TRUE;
}


FORCE_INLINE VOID RtlInitUnicodeStringInline(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(_wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

FORCE_INLINE VOID RtlInitAnsiString(_Out_ PANSI_STRING DestinationString, _In_opt_ PCSTR SourceString)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)_strlen(SourceString)) + sizeof(ANSI_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PCHAR)SourceString;
}



#pragma intrinsic(__readgsqword)
unsigned long long __readgsqword(unsigned long);

FORCE_INLINE LPVOID NtCurrentPeb(VOID)
{
#if defined(_WIN64)
    LPVOID result;
    __asm__ __volatile__(
        "movq %%gs:(%1), %0" // Read QWORD at gs:[offset] into result
        : "=r" (result)      // Output operand: result
        : "r" (0x60)        // Input operand: offset
        :                    // No clobbers
    );
    return result;
#else
    return (PVOID)__readfsdword(0x30);
#endif
}

static PVOID TEBAddress = NULL;

FORCE_INLINE LPVOID NtCurrentTIBOrTEB(VOID)
{
#if defined(_WIN64)
    if (TEBAddress == NULL)
        TEBAddress = (LPVOID)__readgsqword(0x30);
    return TEBAddress;
#else
    if (TEBAddress == NULL)
        TEBAddress = (LPVOID)__readfsdword(0x18);
    return TEBAddress;
#endif
}

FORCE_INLINE PIMAGE_NT_HEADERS ImageCurrentNTHeader(LPVOID address)
{
    IMAGE_DOS_HEADER* dosAddress = (IMAGE_DOS_HEADER*)address;
    return (PIMAGE_NT_HEADERS)((ULONG_PTR)address + dosAddress->e_lfanew);
}

//could be used for junk code
FORCE_INLINE BOOLEAN CheckPESignature(LPVOID address)
{
    IMAGE_DOS_HEADER* dosAddress = (IMAGE_DOS_HEADER*)address;
    IMAGE_NT_HEADERS* ntAddress = (IMAGE_NT_HEADERS*)((ULONG_PTR)address + dosAddress->e_lfanew);

    if (dosAddress->e_magic != IMAGE_DOS_SIGNATURE || ntAddress->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    return 1;
}

FORCE_INLINE PVOID GetModuleBaseAddress(PWSTR name)
{
    PPEB p_peb = (PPEB)NtCurrentPeb();
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)p_peb->Ldr;

    for (PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink; pLdrDataEntry->DllBase != NULL; pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrDataEntry->InLoadOrderLinks.Flink)
    {
        if (CompareUnicode(name, pLdrDataEntry->BaseDllName.Buffer))
            return pLdrDataEntry->DllBase;
    }
    return NULL;
}

FORCE_INLINE PLDR_DATA_TABLE_ENTRY GetCurrentModuleLdr(VOID)
{
    PPEB pPeb = (PPEB)NtCurrentPeb();
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)pPeb->Ldr;

    for (PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink; pLdrDataEntry->DllBase != NULL; pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pLdrDataEntry->InLoadOrderLinks.Flink)
    {
        if (pPeb->ImageBaseAddress == pLdrDataEntry->DllBase)
            return pLdrDataEntry;
    }
    return (PLDR_DATA_TABLE_ENTRY)NULL;
}


/*
FORCE_INLINE PVOID MallocCustom(PSIZE_T size)
{
    char ntAllocate[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', '\0' };
    PNtAllocateVirtualMemory pNtAllocate = (PNtAllocateVirtualMemory)GetProcedureAddressNt(ntAllocate);//"NtAllocateVirtualMemory\0"
    PVOID pAllocated = NULL;
    pNtAllocate((HANDLE)(-1), &pAllocated, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    return pAllocated;
}
*/

FORCE_INLINE VOID MemZero(PVOID add, INT size)
{
    CHAR* byte = (CHAR*)add;
    for (INT i = 0; i < size; i++)
    {
        byte[i] = '\0';
    }
    return;
}