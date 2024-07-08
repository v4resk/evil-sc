from core.controlers.EncryptorsChain import EncryptorsChain
from binascii import hexlify

class ShellcodeControler:
    def __init__(self, shellcode_variable, encryptors_chain):
        self.encryptors_chain = encryptors_chain
        self.shellcode_bytes = self.file_to_bytes(shellcode_variable)
        self.encrypted_shellcode_bytes = self.encrypt_shellcode()

    def file_to_bytes(self,filepath):
        with open(filepath, 'rb') as file:
            byte_array_data = bytes(file.read())
        return byte_array_data

    def encrypt_shellcode(self):
        encrypted_shellcode_bytes = self.shellcode_bytes 
        for key, encryptor in self.encryptors_chain.chain.items():
            encrypted_shellcode_bytes = encryptor.encode(encrypted_shellcode_bytes)
        return encrypted_shellcode_bytes

    def decrypt_shellcode(self):
        decrypted_shellcode_bytes = self.encrypted_shellcode_bytes 
        for key, encryptor in self.encryptors_chain.chain.items():
            decrypted_shellcode_bytes = encryptor.decode(decrypted_shellcode_bytes)
        return decrypted_shellcode_bytes

    def test(self):
        print(f"Plane Shellcode: {self.shellcode_bytes}")
        print()
        print(f"Encoded Shellcode: {self.encrypted_shellcode_bytes}")
        print()
        print(f"Decoded Shellcode: {self.decrypt_shellcode()}")
        print()
        print(f"C Encoded Shellcode: {self.get_encrypted_shellcode_c()}")
        print()
        print(f"C Decoded Shellcode: {self.get_decrypted_shellcode_c()}")

    def get_encrypted_shellcode_bytes(self):
        return self.encrypted_shellcode_bytes

    def get_encrypted_shellcode_c(self):
        shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
        shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
        return shellcode

    def get_decrypted_shellcode_c(self):
        shellcode = hexlify(self.decrypt_shellcode()).decode()
        shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
        return shellcode
    