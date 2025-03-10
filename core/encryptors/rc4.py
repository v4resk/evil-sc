
import secrets
import string
from binascii import hexlify
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
import uuid
from Crypto.Cipher import ARC4

class rc4(Encryptor):
    def __init__(self,platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        # Generate a key for RC4 (typically between 1 and 256 bytes)
        self.key = ''.join(secrets.choice(".+-,:;_%=()" + string.ascii_letters + string.digits) for _ in range(16)).encode()
        self.uuid = uuid.uuid4().hex

    @property
    def c_key(self):
        k = hexlify(self.key).decode()
        return "{" + ",".join([f"0x{k[i:i+2]}" for i in range(0, len(k), 2)]) + "}"

    def encode(self, data):
        if not (isinstance(data, bytes) or isinstance(data, bytearray)):
            data = data.encode()
        cipher = ARC4.new(self.key)
        encrypted = cipher.encrypt(data)
        return encrypted

    def decode(self, data):
        cipher = ARC4.new(self.key)
        return cipher.decrypt(data)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [
                CallComponent(f"length = rc4_decrypt_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.c_key)),
                IncludeComponent("#include <bcrypt.h>")
            ]
            module.mingw_options = "-lbcrypt "
        
        elif self.platform == "windows_cs":
            module.components = [
                CallComponent(f"buf = RC4Encryptor_{self.uuid}.Decrypt(buf);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.c_key)),
                DefineComponent("using System.Runtime.InteropServices;\n"),
            ]

        return module