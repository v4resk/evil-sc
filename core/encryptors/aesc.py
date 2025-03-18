import secrets
import string
import os

from binascii import hexlify

from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
import uuid

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class aesc(Encryptor):
    def __init__(self, platform):
        super().__init__(platform)

        self.key = os.urandom(16)
        self.iv = os.urandom(16)
        self.uuid = uuid.uuid4().hex
        self.c_key = "{" + ",".join([hex(x) for x in self.key]) + "}"
        self.c_iv = "{" + ",".join([hex(x) for x in self.iv]) + "}"


    def encode(self, data):
        if not isinstance(data, (bytes, bytearray)):
            data = data.encode()
        
        # Create AES cipher in CBC mode
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        # Pad the data using PKCS7 and encrypt
        padded_data = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return encrypted

    def decode(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(data), AES.block_size)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [
                CallComponent(f"length = aesc_decrypt_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))
                                .replace("####KEY####", self.c_key)
                                .replace("####IV####", self.c_iv))
            ]
        
        elif self.platform == "windows_cs":
            module.components = [
                CallComponent(f"buf = AesEncryptor_{self.uuid}.Decrypt(buf);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))
                                .replace("####KEY####", f"new byte[] {{{','.join([str(b) for b in self.key])}}}")
                                .replace("####IV####", f"new byte[] {{{','.join([str(b) for b in self.iv])}}}")),
                DefineComponent("using System.Linq;\n")
            ]
        
        elif self.platform == "windows_pwsh":
            # Format byte arrays as explicit [byte] casts
            key_str = "[byte[]]@(" + ",".join([str(b) for b in self.key]) + ")"
            iv_str = "[byte[]]@(" + ",".join([str(b) for b in self.iv]) + ")"
            
            module.components = [
                CallComponent(f"$buf = Invoke-AesDecrypt_{self.uuid} -Data $buf\n"),
                CodeComponent(code.replace("####UUID####", str(self.uuid))
                                .replace("####KEY####", key_str)
                                .replace("####IV####", iv_str))
            ]
        
        return module

    