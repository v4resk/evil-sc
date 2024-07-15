
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
import string
from colorama import init, Fore

from core.controlers.Module import Module
from core.config.config import Config
import uuid as uuidlib


class uuid(Encryptor):
    def __init__(self):
        super().__init__()
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.uuid = uuidlib.uuid4().hex
        self.isStringShellcode = True

    def encode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        
        if len(data) % 16 != 0:
            print(f"{Fore.GREEN}[+] {Fore.WHITE}Shellcode's length not multiplies of 16 bytes - Needed for UUID encoding")
            print(f"{Fore.GREEN}[+] {Fore.WHITE}Adding nullbytes at the end of shellcode, this might break your shellcode.")

            addNullbyte =  b"\x90" * (16-(len(data)%16))
            data += addNullbyte 

        uuid_str = ""
        chunk_size = 16  # Each UUID is 16 bytes
        # Iterate over the byte array in chunks of 16 bytes
        for i in range(0, len(data), chunk_size):
            data_chunk = data[i:i + chunk_size]
            
            # Pad the chunk if it is less than 16 bytes
            if len(data_chunk) < chunk_size:
                padding = chunk_size - len(data_chunk)
                data_chunk += (b'\x90' * padding)
    
            # Convert the chunk to UUID
            uuid_str += f'{uuidlib.UUID(bytes_le=data_chunk)}'
    
        # Remove the trailing newline character
        uuid_str = uuid_str.rstrip('\n')
        return bytearray(uuid_str,'utf-8')
    


    def decode(self, data):
        return data


    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        module.call_component = CallComponent(f"length = uuid_decode_{self.uuid}(encoded, length);")
        module.code_components = CodeComponent(code.replace("####UUID####",str(self.uuid)))
        module.include_components = IncludeComponent("<rpc.h>")
        module.mingw_options = "-lrpcrt4 "

        return module

    def test(self):
        print("hello from UUID encryptor object")