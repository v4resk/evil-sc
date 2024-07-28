
import secrets
import string

from binascii import hexlify

from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.controlers.Module import Module
import uuid

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class aes(Encryptor):
    def __init__(self):
        super().__init__()
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.key = ''.join(secrets.choice(".+-,:;_%=()" + string.ascii_letters + string.digits) for _ in range(36)).encode()
        self.salt = ''.join(secrets.choice(".+-,:;_%=()" + string.ascii_letters + string.digits) for _ in range(18)).encode()
        self.derived_key = PBKDF2(self.key.decode(), self.salt, 32, 1000)
        self.iv = PBKDF2(self.key.decode(), self.salt, 48, 1000)[32:]
        self.uuid = uuid.uuid4().hex

    @property
    def c_key(self):
        k = hexlify(self.derived_key).decode()
        return "{" + ",".join([f"0x{k[i:i+2]}" for i in range(0, len(k), 2)]) + "}"

    @property
    def c_iv(self):
        k = hexlify(self.iv).decode()
        return "{" + ",".join([f"0x{k[i:i+2]}" for i in range(0, len(k), 2)]) + "}"

    def encode(self, data):
        if not (isinstance(data, bytes) or isinstance(data, bytearray)):
            data = data.encode()
        cipher = AES.new(self.derived_key, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return encrypted

    def decode(self, data):
        cipher = AES.new(self.derived_key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(data), AES.block_size)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        module.components = [
            CallComponent(f"length = aes_decrypt_{self.uuid}(encoded, length);"),
            CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.c_key).replace("####IV####", self.c_iv)),
            IncludeComponent("<bcrypt.h>")
        ]

        module.mingw_options = "-lbcrypt "

        return module