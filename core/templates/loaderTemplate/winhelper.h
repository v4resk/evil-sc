#pragma once
#include <windows.h>



typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE Handle
);

// Function declarations
pNtCreateThreadEx NtCreateThreadEx;
pNtFreeVirtualMemory NtFreeVirtualMemory;
pNtProtectVirtualMemory NtProtectVirtualMemory;
pNtWriteVirtualMemory NtWriteVirtualMemory;
pNtAllocateVirtualMemory NtAllocateVirtualMemory;
pNtWaitForSingleObject NtWaitForSingleObject;
pNtClose NtClose;