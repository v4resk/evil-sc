int xor_encode_####UUID####(unsigned char* data, int data_len)
{
    const char* key = "####KEY####";
    int key_len = ####KEY_LENGTH####;
    
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
