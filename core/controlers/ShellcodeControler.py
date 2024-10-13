from binascii import hexlify
from core.config.config import Config

debug_mode = Config().get("DEBUG", "SHELLCODE")   

class ShellcodeControler:
    def __init__(self, shellcode_variable, encryptors_chain):
        self.encryptors_chain = encryptors_chain
        self.shellcode_bytes = self.file_to_bytes(shellcode_variable) 
        self.encrypted_shellcode_bytes = self.encrypt_shellcode()
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

    def decrypt_shellcode(self):
        decrypted_shellcode_bytes = self.encrypted_shellcode_bytes 
        for key, encryptor in self.encryptors_chain.chain.items():
            decrypted_shellcode_bytes = encryptor.decode(decrypted_shellcode_bytes)
        return decrypted_shellcode_bytes

    def test(self):
        print(f"C Plane Shellcode: {self.get_shellcode(self.shellcode_bytes)}")
        print()
        print(f"C Encoded Shellcode: {self.get_encrypted_shellcode_c()}")
        print()
        print(f"C Decoded Shellcode: {self.get_decrypted_shellcode_c()}")

    def get_encrypted_shellcode_bytes(self):
        return self.encrypted_shellcode_bytes
    
    def get_encrypted_shellcode_len(self):
        return self.shellcode_len

    def get_encrypted_shellcode_c(self):
        if len(self.encryptors_chain.chain.items()) == 0:
            return self.get_shellcode(self.shellcode_bytes)

        # Check if some enc should be returned as "String" format
        for key, encryptor in self.encryptors_chain.chain.items():
            if not encryptor.isStringShellcode:
                return self.get_shellcode(self.encrypted_shellcode_bytes)
            else:
                print("[*] String shellcode")
                #return self.get_shellcode(encrypted_shellcode_bytes)
                return "\"" +self.encrypted_shellcode_bytes.decode("utf-8")+"\""
            break
        #return shellcode

    def get_encrypted_shellcode_pwsh(self):
        return self.get_shellcode(self.encrypted_shellcode_bytes, format="pwsh")
     
    
    def get_plain_shellcode_c(self):
        shellcode = hexlify(self.shellcode_bytes).decode()
        shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
        return shellcode

    def get_decrypted_shellcode_c(self):
        shellcode = hexlify(self.decrypt_shellcode()).decode()
        shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
        return shellcode
    
    def get_shellcode(self,shellcode_bytes, string = False, format="C"):
        if format == "C":
            if string is False:
                shellcode = hexlify(shellcode_bytes).decode()
                shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
                return shellcode
            else:
                return "\"" +shellcode_bytes.decode("utf-8")+"\""
        elif format == "pwsh":
            shellcode = hexlify(shellcode_bytes).decode()
            shellcode = ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)])
            return shellcode
    