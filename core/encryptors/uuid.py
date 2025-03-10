from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from colorama import Fore

from core.controlers.Module import Module
import uuid as uuidlib


class uuid(Encryptor):
    def __init__(self,platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.uuid = uuidlib.uuid4().hex
        self.isStringShellcode = True

    def encode(self, data):
        # Convert data to bytearray if it's not already
        if not isinstance(data, bytearray):
            data = bytearray(data)
        
        # Calculate padding needed
        padding_needed = (16 - (len(data) % 16)) % 16
        if padding_needed > 0:
            data.extend(b'\x00' * padding_needed)
        
        # Process data in chunks of 16 bytes
        uuid_str = ""
        for i in range(0, len(data), 16):
            uuid_str += f'{uuidlib.UUID(bytes_le=bytes(data[i:i+16]))}'
        
        print(f"{Fore.GREEN}[+] {Fore.WHITE}Shellcode's length not multiplies of 16 bytes - Needed for UUID encoding")
        print(f"{Fore.GREEN}[+] {Fore.WHITE}Adding nullbytes at the end of shellcode, this might break your shellcode.")
        print()
        return bytearray(uuid_str.encode())
    


    def decode(self, data):
        return data


    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        module.components = [
            CallComponent(f"length = uuid_decode_{self.uuid}(encoded, length);"),
            CodeComponent(code.replace("####UUID####",str(self.uuid))),
            IncludeComponent("#include <rpc.h>")
        ]
        
        module.mingw_options = "-lrpcrt4 "

        return module

    def test(self):
        print("hello from UUID encryptor object")