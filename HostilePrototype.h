#pragma once
#include "HostileHeader.h"

//
// Thread Local Storage
//
typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK) (PVOID DllHandle, DWORD Reason, PVOID Reserved);

typedef VOID(NTAPI* PIO_APC_ROUTINE)(_In_ PVOID ApcContext, _In_ struct _IO_STATUS_BLOCK* IoStatusBlock, //PIO_STATUS_BLOCK
    _In_ ULONG Reserved
    );

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef NTSTATUS NTAPI
NtShutdownSystem(
    _In_ enum _SHUTDOWN_ACTION Action
); typedef NtShutdownSystem* PNtShutdownSystem;

typedef NTSYSAPI NTSTATUS NTAPI
RtlCreateProcessParametersEx(
    _Out_  RTL_USER_PROCESS_PARAMETERS** pProcessParameters,//PRTL_USER_PROCESS_PARAMETERS* struct RTL_USER_PROCESS_PARAMETERS**
    _In_ PUNICODE_STRING ImagePathName,//PUNICODE_STRING
    _In_opt_ PUNICODE_STRING DllPath,//PUNICODE_STRING
    _In_opt_ PUNICODE_STRING CurrentDirectory,//PUNICODE_STRING
    _In_opt_ PUNICODE_STRING CommandLine,//PUNICODE_STRING
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,//PUNICODE_STRING
    _In_opt_ PUNICODE_STRING DesktopInfo,//PUNICODE_STRING
    _In_opt_ PUNICODE_STRING ShellInfo,//PUNICODE_STRING
    _In_opt_ PUNICODE_STRING RuntimeData,//PUNICODE_STRING
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
); typedef RtlCreateProcessParametersEx* PRtlCreateProcessParametersEx;

typedef NTSYSCALLAPI NTSTATUS NTAPI
NtCreateProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle
); typedef NtCreateProcess* PNtCreateProcess;

typedef  NTSTATUS NTAPI
NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    _In_opt_ RTL_USER_PROCESS_PARAMETERS* ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
    _Inout_  PS_CREATE_INFO* CreateInfo,//PPS_CREATE_INFO
    _In_opt_ PS_ATTRIBUTE_LIST* AttributeList//PPS_ATTRIBUTE_LIST
); typedef NtCreateUserProcess* PNtCreateUserProcess;

typedef NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
); typedef NtAllocateVirtualMemory* PNtAllocateVirtualMemory;

typedef NTSTATUS NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
); typedef NtFreeVirtualMemory* PNtFreeVirtualMemory;

typedef NTSTATUS NTAPI RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,                                  //_Out_
    PWSTR SourceString                                                  //_In_opt_z_
); typedef RtlInitUnicodeString* PRtlInitUnicodeString;

typedef NTSTATUS NTAPI
NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ enum _PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
); typedef NtQueryInformationProcess* PNtQueryInformationProcess;

typedef NTSTATUS NTAPI
NtCreateDebugObject(
    _Out_ PHANDLE DebugObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags
); typedef NtCreateDebugObject* PNtCreateDebugObject;

typedef INT C snprintff(CHAR* const Buffer, const size_t BufferCount, const CHAR* const Format, ...);
typedef snprintff* Psnprintff;

typedef
NTSTATUS
NTAPI
NtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ struct _IO_STATUS_BLOCK* IoStatusBlock,
    PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
); typedef NtReadFile* PNtReadFile;

typedef NTSTATUS NTAPI NtWriteFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ struct _IO_STATUS_BLOCK* IoStatusBlock,//PIO_STATUS_BLOCK
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
); typedef NtWriteFile* PNtWriteFile;

typedef NTSTATUS NTAPI
NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
); typedef NtProtectVirtualMemory* PNtProtectVirtualMemory;

typedef NTSTATUS NTAPI
NtRemoveProcessDebug(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle
); typedef NtRemoveProcessDebug* PNtRemoveProcessDebug;

//----
typedef NTSTATUS NTAPI
NtDebugActiveProcess(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle
); typedef NtDebugActiveProcess* PNtDebugActiveProcess;

typedef NTSTATUS NTAPI
NtDebugContinue(
    _In_ HANDLE DebugObjectHandle,
    _In_ struct _CLIENT_ID* ClientId,
    _In_ NTSTATUS ContinueStatus
); typedef NtDebugContinue* PNtDebugContinue;

typedef NTSTATUS NTAPI
NtSetInformationDebugObject(
    _In_ HANDLE DebugObjectHandle,
    _In_ enum _DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
    _In_ PVOID DebugInformation,
    _In_ ULONG DebugInformationLength,
    _Out_opt_ PULONG ReturnLength
); typedef NtSetInformationDebugObject* PNtSetInformationDebugObject;

typedef NTSTATUS NTAPI
NtWaitForDebugEvent(
    _In_ HANDLE DebugObjectHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_ struct _DBGUI_WAIT_STATE_CHANGE* WaitStateChange
); typedef NtWaitForDebugEvent* PNtWaitForDebugEvent;

typedef ULONG STDAPIVCALLTYPE
DbgPrint(
    PCSTR Format,
    ...
); typedef DbgPrint* PDbgPrint;

typedef VOID NTAPI
DbgBreakPointWithStatus(
    _In_ ULONG Status
); typedef DbgBreakPointWithStatus* PDbgBreakPointWithStatus;

typedef ULONG NTAPI
DbgPrompt(
    _In_ PCCH Prompt,
    PCH Response,
    _In_ ULONG Length
); typedef DbgPrompt* PDbgPrompt;

typedef ULONG NTAPI
RtlGetNtGlobalFlags(
    VOID
); typedef RtlGetNtGlobalFlags* PRtlGetNtGlobalFlags;

typedef NTSTATUS NTAPI
NtRaiseHardError(
    _In_ NTSTATUS ErrorStatus,
    _In_ ULONG NumberOfParameters,
    _In_ ULONG UnicodeStringParameterMask,
    _In_reads_(NumberOfParameters) PULONG_PTR Parameters,
    _In_ ULONG ValidResponseOptions,
    _Out_ PULONG Response
); typedef NtRaiseHardError* PNtRaiseHardError;

typedef NTSTATUS NTAPI
RtlAdjustPrivilege(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled
); typedef RtlAdjustPrivilege* PRtlAdjustPrivilege;

typedef NTSTATUS NTAPI
RtlAcquirePrivilege(
    _In_ PULONG Privilege,
    _In_ ULONG NumPriv,
    _In_ ULONG Flags,
    _Out_ PVOID* ReturnedState
); typedef RtlAcquirePrivilege* PRtlAcquirePrivilege;

typedef NTSTATUS NTAPI
NtOpenProcessToken(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle
); typedef NtOpenProcessToken* PNtOpenProcessToken;

typedef NTSTATUS NTAPI
NtOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle
); typedef NtOpenProcessTokenEx* PNtOpenProcessTokenEx;

typedef NTSTATUS NTAPI
NtOpenThreadToken(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN OpenAsSelf,
    _Out_ PHANDLE TokenHandle
); typedef NtOpenThreadToken* PNtOpenThreadToken;

typedef NTSTATUS NTAPI
NtOpenThreadTokenEx(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN OpenAsSelf,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle
); typedef NtOpenThreadTokenEx* PNtOpenThreadTokenEx;

typedef NTSTATUS NTAPI
NtSetInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ enum _TOKEN_INFORMATION_CLASS TokenInformationClass,
    _In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength
); typedef NtSetInformationToken* PNtSetInformationToken;

typedef NTSTATUS NTAPI
NtAdjustPrivilegesToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ struct _TOKEN_PRIVILEGES* NewState,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) struct _TOKEN_PRIVILEGES* PreviousState,
    _Out_opt_ PULONG ReturnLength
); typedef NtAdjustPrivilegesToken* PNtAdjustPrivilegesToken;

typedef NTSTATUS NTAPI
NtImpersonateThread(
    _In_ HANDLE ServerThreadHandle,
    _In_ HANDLE ClientThreadHandle,
    _In_ struct _SECURITY_QUALITY_OF_SERVICE* SecurityQos
); typedef NtImpersonateThread* PNtImpersonateThread;

typedef NTSTATUS NTAPI
NtSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ enum _THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
); typedef NtSetInformationThread* PNtSetInformationThread;

typedef NTSTATUS NTAPI NtDuplicateToken(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ struct _OBJECT_ATTRIBUTES* ObjectAttributes,
    _In_ BOOLEAN EffectiveOnly,
    _In_ enum _TOKEN_TYPE Type,
    _Out_ PHANDLE NewTokenHandle
); typedef NtDuplicateToken* PNtDuplicateToken;

typedef NTSTATUS NTAPI
NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ struct _OBJECT_ATTRIBUTES* ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ struct _PS_ATTRIBUTE_LIST* AttributeList
); typedef NtCreateThreadEx* PNtCreateThreadEx;

typedef
NTSTATUS
NTAPI
NtCreateProcessEx(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    ULONG Reserved // JobMemberLevel
); typedef NtCreateProcessEx* PNtCreateProcessEx;

typedef
NTSTATUS
NTAPI
NtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ struct _OBJECT_ATTRIBUTES* ObjectAttributes,//POBJECT_ATTRIBUTES
    _In_opt_ struct _CLIENT_ID* ClientId//PCLIENT_ID
); typedef NtOpenProcess* PNtOpenProcess;

typedef
VOID
NTAPI
KiUserExceptionDispatcher(
    EXCEPTION_RECORD* ExceptionRecord,
    CONTEXT* Context
); typedef KiUserExceptionDispatcher* PKiUserExceptionDispatcher;

typedef KiUserExceptionDispatcher KiUserExceptionDispatch, * PKiUserExceptionDispatch;

typedef
VOID
NTAPI
KiRaiseUserExceptionDispatcher(
    VOID
); typedef KiRaiseUserExceptionDispatcher* PKiRaiseUserExceptionDispatcher;

typedef
VOID
NTAPI
KiUserCallbackDispatcher(
    ULONG Index,
    PVOID Argument,
    ULONG ArgumentLength
); typedef KiUserCallbackDispatcher* PKiUserCallbackDispatcher;

typedef 
NTSTATUS
NTAPI
NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
); typedef NtWaitForSingleObject* PNtWaitForSingleObject;

typedef NTSTATUS LdrLoadDll(
    _In_opt_	PWSTR DllPath,
    _In_opt_	PULONG DllCharacteristics,
    _In_		PUNICODE_STRING DllName,
    _Out_		PVOID* DllHandle
); typedef LdrLoadDll* PLdrLoadDll;