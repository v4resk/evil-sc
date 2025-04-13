import secrets
import string
import struct
from itertools import islice, cycle
import uuid
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.controlers.Module import Module
from Crypto.Util import strxor

class xor(Encryptor):
    def __init__(self, platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.key = ''.join(secrets.choice(".+-,:;_%=()" + string.ascii_letters + string.digits) for _ in range(12)).encode()
        self.uuid = uuid.uuid4().hex

    def slow_encode(self, data):
        encoded = b""
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        for i in range(len(data)):
            print(f"    [>] Progress: {i * 100 / (len(data) - 1):.2f}%     ", end='\r')
            encoded += struct.pack("B", (data[i] ^ (self.key[i % len(self.key)])))
        print()
        return encoded

    def encode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        return strxor.strxor(data, bytearray(islice(cycle(self.key), len(data))))

    def decode(self, data):
        return self.encode(data)


    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [
                CallComponent(f"length = xor_encode_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####KEY_LENGTH####", str(len(self.key))).replace("####UUID####",str(self.uuid)))
            ]
        elif self.platform == "linux":
            module.components = [
                CallComponent(f"length = xor_encode_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####KEY_LENGTH####", str(len(self.key))).replace("####UUID####",str(self.uuid)))
            ]
        elif self.platform == "windows_cs":
            module.components = [
                CallComponent(f"buf = XorEncoder_{self.uuid}.Decode(buf);"),
                CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####UUID####",str(self.uuid)))
            ]
        
        elif self.platform == "windows_aspx":
            module.components = [
                CallComponent(f"buf = XorEncoder_{self.uuid}.Decode(buf);"),
                CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####UUID####",str(self.uuid)))
            ]   

        elif self.platform == "windows_pwsh":
            module.components = [
                CallComponent(f"$buf = Invoke-Xor{self.uuid} -Data $buf\n"),
                CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####UUID####",str(self.uuid)))
            ]    

        elif self.platform == "windows_vba":
            module.components = [
                CallComponent(f"XORDecode{self.uuid} buf\n"),
                CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####UUID####",str(self.uuid)))
            ] 
        elif self.platform == "windows_vbs":
            module.components = [
                CallComponent(f"XORDecode{self.uuid} buf\n"),
                CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####UUID####",str(self.uuid)))
            ] 

        return module

    def test(self):
        print("hello from xor encryptor object")