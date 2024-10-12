int base64_decode_####UUID####(unsigned char* encoded, int length)
 {


    printf("\n[*] Before BASE64 values: {");
    for (DWORD i = 0; i < length; i++) {
        printf("0x%02x", encoded[i]);
        if (i < length - 1) {
            printf(",");
        }
    }
    printf("}\n");

    DWORD dwDecodedSize = 0;
    BOOL result = CryptStringToBinaryA((LPCSTR)encoded, length, CRYPT_STRING_BASE64, NULL, &dwDecodedSize, NULL, NULL);
    if (!result) {
        printf("[-] Error calculating decoded size\n");
        return -1;
    }

    unsigned char* decoded = (unsigned char*)malloc(dwDecodedSize);
    if (decoded == NULL) {
        printf("[-] Memory allocation failed\n");
        return -1;
    }

    result = CryptStringToBinaryA((LPCSTR)encoded, length, CRYPT_STRING_BASE64, decoded, &dwDecodedSize, NULL, NULL);
    if (!result) {
        printf("[-] Error decoding base64\n");
        free(decoded);
        return -1;
    }

    // Debug statement to print the decoded values
    printf("\n[*] After BASE64 values: {");
    for (DWORD i = 0; i < dwDecodedSize; i++) {
        printf("0x%02x", decoded[i]);
        if (i < dwDecodedSize - 1) {
            printf(",");
        }
    }
    printf("}\n");

    memcpy(encoded, decoded, dwDecodedSize);
    free(decoded);

    return dwDecodedSize;
}