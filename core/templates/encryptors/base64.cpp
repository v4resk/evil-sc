int base64_decode_####UUID####(unsigned char* data, int data_len)
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
}