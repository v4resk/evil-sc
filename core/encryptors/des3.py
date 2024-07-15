
import secrets
import string

from binascii import hexlify


from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.controlers.Module import Module
from core.config.config import Config
import uuid

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class des3(Encryptor):
    def __init__(self):
        super().__init__()
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]

        # Generate a 24-byte key
        self.key = ''.join(secrets.choice(".+-,:;_%=()" + string.ascii_letters + string.digits) for _ in range(36)).encode()
        self.salt = ''.join(secrets.choice(".+-,:;_%=()" + string.ascii_letters + string.digits) for _ in range(18)).encode()

        # Derive a 24-byte key for 3DES
        self.derived_key = PBKDF2(self.key.decode(), self.salt, 24, 1000)

        # Derive an 8-byte IV for 3DES
        self.iv = PBKDF2(self.key.decode(), self.salt, 16, 1000)[8:]

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
        cipher = DES3.new(self.derived_key, DES3.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(pad(data, DES3.block_size))
        return encrypted

    def decode(self, data):
        cipher = DES3.new(self.derived_key, DES3.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(data), DES3.block_size)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        module.call_component = CallComponent(f"length = des3_decrypt_{self.uuid}(encoded, length);")
        module.code_components = CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.c_key).replace("####IV####", self.c_iv))
        module.include_components = IncludeComponent("<bcrypt.h>")
        module.mingw_options = "-lbcrypt "

        return module