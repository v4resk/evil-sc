int nop_decode_####UUID####(unsigned char* encoded, int length)
{
    int data_len = 0;
    for (int i = 0; i < length; i++) {
        if (i % 2 == 0){
            encoded[data_len] = encoded[i];
            data_len++;
        }
    }

    printf("\n");
    printf("DEBUG:After NOP:");
    for (size_t i = 0; i < data_len; i++) {
        printf("0x%02x,", encoded[i]);
    }
    printf("\n\n");

    return data_len;
}