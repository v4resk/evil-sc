int rc4_decrypt_####UUID####(unsigned char* encoded, int length) {

    unsigned char key[] = ####KEY####;
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
}