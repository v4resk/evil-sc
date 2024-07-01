import base64
import secrets
import string
import struct
from itertools import islice, cycle

from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.controlers.Module import Module
from Crypto.Util import strxor
from core.config.config import Config


class xor(Encryptor):
    def __init__(self):
        super().__init__()
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.key = ''.join(secrets.choice(".+-,:;_%=()" + string.ascii_letters + string.digits) for _ in range(12)).encode()

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

        module.call_component = CallComponent("length = xor_encode(encoded, length);")
        module.code_components = CodeComponent(code.replace("####KEY####", self.key.decode()).replace("####KEY_LENGTH####", str(len(self.key))))
        

        return module

    def test(self):
        print("hello")