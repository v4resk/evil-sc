int base64_decode_####UUID####(unsigned char* data, int data_len)
{
    

    for (int i = 0; i < data_len; i++){
        data[i] = (data[i] ^ (unsigned char)key[i % key_len]);
    }
    return data_len;
}