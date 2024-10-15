from binascii import hexlify
from core.config.config import Config

debug_mode = Config().get("DEBUG", "SHELLCODE")   

class ShellcodeControler:
    def __init__(self, shellcode_variable, encryptors_chain, platform):
        self.encryptors_chain = encryptors_chain
        self.platform = platform
        self.shellcode_bytes = self.file_to_bytes(shellcode_variable) 
        self.encrypted_shellcode_bytes = self.encrypt_shellcode()
        self.chain_ending_w_str = self.check_str_encryptors()
        self.shellcode_len = len(self.encrypted_shellcode_bytes)


    def file_to_bytes(self,filepath):
        with open(filepath, 'rb') as file:
            byte_array_data = bytes(file.read())
        return byte_array_data

    def encrypt_shellcode(self):
        i = 0
        encrypted_shellcode_bytes = self.shellcode_bytes 
        for key, encryptor in reversed(self.encryptors_chain.chain.items()):
            
            ### DEBUG ####
            if debug_mode == "True":
                print(f"{encryptor.to_string()}{i} Before Encode: {self.get_shellcode(encrypted_shellcode_bytes)}")
                print()

            encrypted_shellcode_bytes = encryptor.encode(encrypted_shellcode_bytes)

            ### DEBUG ####
            if debug_mode == "True":
                print(f"{encryptor.to_string()} n°{i} After Encode: {self.get_shellcode(encrypted_shellcode_bytes,encryptor.isStringShellcode)}")
                print()
                i = i+1
        return encrypted_shellcode_bytes


    
    def check_str_encryptors(self):
        if len(self.encryptors_chain.chain.items()) == 0:
            return False
        for key, encryptor in self.encryptors_chain.chain.items():
            if not encryptor.isStringShellcode:
                return False
            else:
                return True
            break

    
    def get_encrypted_shellcode_len(self):
        if self.chain_ending_w_str is False:
            return self.shellcode_len
        else:
            return self.shellcode_len + 2

    def get_encrypted_shellcode_c(self):
        #return shellcode
        # Check if some enc should be returned as "String" format
        if not self.chain_ending_w_str:
            return self.get_shellcode(self.encrypted_shellcode_bytes)
        else:
            print("[*] String shellcode")
            #return self.get_shellcode(encrypted_shellcode_bytes)
            return "\"" +self.encrypted_shellcode_bytes.decode("utf-8")+"\""




    def get_encrypted_shellcode_pwsh(self):
        return self.get_shellcode(self.encrypted_shellcode_bytes, format="pwsh")
     


    def get_shellcode(self):
        if self.platform == "windows_cpp" or self.platform == "windows_cs" or self.platform == "linux":
            if self.chain_ending_w_str is False:
                shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
                shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
                return shellcode
            else:
                print("[*] String shellcode")
                return "\"" +self.encrypted_shellcode_bytes.decode("utf-8")+"\\0"+"\""

        
        elif self.platform == "windows_pwsh":
            if self.chain_ending_w_str is False:
                shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
                shellcode = ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)])
                shellcode = f"[Byte[]] ({shellcode})"
                return shellcode
            else:
                print("[*] String shellcode")
                return "\"" +self.encrypted_shellcode_bytes.decode("utf-8")+"\""
    