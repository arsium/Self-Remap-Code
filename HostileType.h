#pragma once
#include "HostileHeader.h"

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef FLOAT* PFLOAT;
typedef BOOL near* PBOOL;
typedef BOOL far* LPBOOL;
typedef BYTE near* PBYTE;
typedef BYTE far* LPBYTE;
typedef int near* PINT;
typedef int far* LPINT;
typedef WORD near* PWORD;
typedef WORD far* LPWORD;
typedef long far* LPLONG;
typedef DWORD near* PDWORD;
typedef DWORD far* LPDWORD;
typedef void far* LPVOID;
typedef CONST void far* LPCVOID;

typedef BYTE  BOOLEAN;
typedef BOOLEAN* PBOOLEAN;
typedef void* HANDLE;
typedef void* PVOID;

typedef char                CHAR;
typedef signed char         INT8;
typedef unsigned char       UCHAR;
typedef unsigned char       UINT8;
typedef unsigned char       BYTE;
typedef short               SHORT;
typedef signed short        INT16;
typedef unsigned short      USHORT;
typedef unsigned short      UINT16;
typedef unsigned short      WORD;
typedef int                 INT;
typedef signed int          INT32;
typedef unsigned int        UINT;
typedef unsigned int        UINT32;
typedef long                LONG;
typedef unsigned long       ULONG;
typedef unsigned long       DWORD;
typedef long long               LONGLONG;
typedef long long               LONG64;
typedef signed long long      RtlINT64;
typedef unsigned long long    ULONGLONG;
typedef unsigned long long    DWORDLONG;
typedef unsigned long long    ULONG64;
typedef unsigned long long    DWORD64;
typedef unsigned long long    UINT64;
typedef unsigned short WCHAR;

#ifdef UNICODE
typedef WCHAR TBYTE;
#else
typedef unsigned char TBYTE;
#endif
typedef CHAR* PCHAR, * LPCH, * PCH;
typedef CONST CHAR* LPCCH, * PCCH;

#define ANSI_NULL ((CHAR)0)     
#define UNICODE_NULL ((WCHAR)0) 
#define UNICODE_STRING_MAX_BYTES ((WORD  ) 65534) 
#define UNICODE_STRING_MAX_CHARS (32767) 

typedef _Null_terminated_ CHAR* NPSTR, * LPSTR, * PSTR;
typedef _Null_terminated_ PSTR* PZPSTR;
typedef _Null_terminated_ CONST PSTR* PCZPSTR;
typedef _Null_terminated_ CONST CHAR* LPCSTR, * PCSTR;
typedef _Null_terminated_ PCSTR* PZPCSTR;
typedef _Null_terminated_ CONST PCSTR* PCZPCSTR;

typedef _Null_terminated_ CHAR* PZZSTR;
typedef _Null_terminated_ CONST CHAR* PCZZSTR;

typedef  CHAR* PNZCH;
typedef  CONST CHAR* PCNZCH;

#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE  1
//
// Neutral ANSI/UNICODE types and macros
//

typedef WCHAR* PWCHAR, * LPWCH, * PWCH;
typedef CONST WCHAR* LPCWCH, * PCWCH;

typedef _Null_terminated_ WCHAR* NWPSTR, * LPWSTR, * PWSTR;
typedef _Null_terminated_ PWSTR* PZPWSTR;
typedef _Null_terminated_ CONST PWSTR* PCZPWSTR;
typedef _Null_terminated_ WCHAR UNALIGNED * LPUWSTR, * PUWSTR;
typedef _Null_terminated_ CONST WCHAR* LPCWSTR, * PCWSTR;
typedef _Null_terminated_ PCWSTR* PZPCWSTR;
typedef _Null_terminated_ CONST PCWSTR* PCZPCWSTR;
typedef _Null_terminated_ CONST WCHAR UNALIGNED* LPCUWSTR, * PCUWSTR;

typedef _NullNull_terminated_ WCHAR* PZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR* PCZZWSTR;
typedef _NullNull_terminated_ WCHAR UNALIGNED* PUZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR UNALIGNED* PCUZZWSTR;

typedef  WCHAR* PNZWCH;
typedef  CONST WCHAR* PCNZWCH;
typedef  WCHAR UNALIGNED* PUNZWCH;
typedef  CONST WCHAR UNALIGNED* PCUNZWCH;


typedef WCHAR TCHAR, * PTCHAR;
//typedef WCHAR TBYTE, * PTBYTE;

typedef LPWCH LPTCH, PTCH;
typedef LPCWCH LPCTCH, PCTCH;
typedef LPWSTR PTSTR, LPTSTR;
typedef LPCWSTR PCTSTR, LPCTSTR;
typedef LPUWSTR PUTSTR, LPUTSTR;
typedef LPCUWSTR PCUTSTR, LPCUTSTR;
typedef LPWSTR LP;
typedef PZZWSTR PZZTSTR;
typedef PCZZWSTR PCZZTSTR;
typedef PUZZWSTR PUZZTSTR;
typedef PCUZZWSTR PCUZZTSTR;
typedef PZPWSTR PZPTSTR;
typedef PNZWCH PNZTCH;
typedef PCNZWCH PCNZTCH;
typedef PUNZWCH PUNZTCH;
typedef PCUNZWCH PCUNZTCH;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;


typedef STRING UTF8_STRING;
typedef PSTRING PUTF8_STRING;

typedef const STRING* PCSTRING;
typedef const ANSI_STRING* PCANSI_STRING;
typedef const OEM_STRING* PCOEM_STRING;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#if defined(_WIN64)
typedef long long INT_PTR, * PINT_PTR;
typedef unsigned long long UINT_PTR, * PUINT_PTR;

typedef long long LONG_PTR, * PLONG_PTR;
typedef unsigned long long ULONG_PTR, * PULONG_PTR;

#define __int3264   __int64

#else
typedef _W64 int INT_PTR, * PINT_PTR;
typedef _W64 unsigned int UINT_PTR, * PUINT_PTR;

typedef _W64 long LONG_PTR, * PLONG_PTR;
typedef _W64 unsigned long ULONG_PTR, * PULONG_PTR;

#define __int3264   __int32

#endif

#if defined(_AMD64_)

typedef union DECLSPEC_ALIGN(16) _SLIST_HEADER {
    struct {  // original struct
        ULONGLONG Alignment;
        ULONGLONG Region;
    } DUMMYSTRUCTNAME;
    struct {  // x64 16-byte header
        ULONGLONG Depth : 16;
        ULONGLONG Sequence : 48;
        ULONGLONG Reserved : 4;
        ULONGLONG NextEntry : 60; // last 4 bits are always 0's
    } HeaderX64;
} SLIST_HEADER, * PSLIST_HEADER;

#elif defined(_ARM64_)

// ARM64_WORKITEM: should this be merged with AMD64 above?
typedef union DECLSPEC_ALIGN(16) _SLIST_HEADER {
    struct {  // original struct
        ULONGLONG Alignment;
        ULONGLONG Region;
    } DUMMYSTRUCTNAME;
    struct {  // ARM64 16-byte header
        ULONGLONG Depth : 16;
        ULONGLONG Sequence : 48;
        ULONGLONG Reserved : 4;
        ULONGLONG NextEntry : 60; // last 4 bits are always 0's
    } HeaderArm64;
} SLIST_HEADER, * PSLIST_HEADER;

#elif defined(_X86_)

typedef union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct {
        SLIST_ENTRY Next;
        WORD   Depth;
        WORD   CpuId;
    } DUMMYSTRUCTNAME;
} SLIST_HEADER, * PSLIST_HEADER;

#elif defined(_ARM_)

typedef union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct {
        SLIST_ENTRY Next;
        WORD   Depth;
        WORD   Reserved;
    } DUMMYSTRUCTNAME;
} SLIST_HEADER, * PSLIST_HEADER;

#endif

typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;


/*#if defined(MIDL_PASS)
typedef struct _LARGE_INTEGER {
    LONGLONG QuadPart;
} LARGE_INTEGER;
#else // MIDL_PASS
typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;
#endif //MIDL_PASS*/

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER* PLARGE_INTEGER;

#if defined(MIDL_PASS)
typedef struct _ULARGE_INTEGER {
    ULONGLONG QuadPart;
} ULARGE_INTEGER;
#else // MIDL_PASS
typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;
#endif //MIDL_PASS

typedef ULARGE_INTEGER* PULARGE_INTEGER;

typedef ULONG_PTR   DWORD_PTR;
typedef LONG_PTR    SSIZE_T;
typedef ULONG_PTR   SIZE_T;

typedef ULONG_PTR KAFFINITY;
typedef KAFFINITY* PKAFFINITY;


typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

//
// The following types are guaranteed to be signed and 32 bits wide.
//

typedef signed int LONG32, * PLONG32;

//
// The following types are guaranteed to be unsigned and 32 bits wide.
//

typedef unsigned int ULONG32, * PULONG32;
typedef unsigned int DWORD32, * PDWORD32;

#ifdef _WIN64
typedef long long             ptrdiff_t;
typedef unsigned long long    size_t;
#else
typedef _W64 int            ptrdiff_t;
typedef _W64 unsigned int   size_t;
#endif

typedef DWORD LCID;
typedef PDWORD PLCID;
typedef WORD   LANGID;

typedef LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;

typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;

typedef HANDLE* PHANDLE;

typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;

typedef PVOID PSECURITY_DESCRIPTOR;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef ULONG_PTR SIZE_T, * PSIZE_T;
typedef LONG_PTR SSIZE_T, * PSSIZE_T;

typedef ULONG* PULONG;
typedef USHORT* PUSHORT;
typedef UCHAR* PUCHAR;

typedef struct _LUID {
    DWORD LowPart;
    LONG HighPart;
} LUID, * PLUID;