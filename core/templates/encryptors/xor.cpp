int xor_encode_####UUID####(unsigned char* data, int data_len)
{
    const char* key = "####KEY####";
    int key_len = ####KEY_LENGTH####;
    
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
