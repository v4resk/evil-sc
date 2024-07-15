
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
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class rc4(Encryptor):
    def __init__(self):
        super().__init__()
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

        module.call_component = CallComponent(f"length = rc4_decrypt_{self.uuid}(encoded, length);")
        module.code_components = CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.c_key))
        module.include_components = IncludeComponent("<bcrypt.h>")
        module.mingw_options = "-lbcrypt "

        return module