import secrets
import string
from binascii import hexlify
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.controlers.Module import Module
import uuid

class cesar(Encryptor):
    def __init__(self, platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        # Random shift value between 1-255 to avoid 0
        self.shift = secrets.randbelow(254) + 1
        self.uuid = uuid.uuid4().hex

    def encode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        
        result = bytearray()
        for byte in data:
            # Apply Caesar shift with wraparound
            shifted = (byte + self.shift) % 256
            result.append(shifted)
        
        return bytes(result)

    def decode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        
        result = bytearray()
        for byte in data:
            # Reverse Caesar shift with wraparound
            shifted = (byte - self.shift) % 256
            result.append(shifted)
        
        return bytes(result)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_vba":
            module.components = [
                CallComponent(f"CesarDecode{self.uuid} buf\n"),
                CodeComponent(code.replace("####SHIFT####", str(self.shift))
                                .replace("####UUID####", str(self.uuid)))
            ]
        elif self.platform == "windows_vbs":
            module.components = [
                CallComponent(f"CesarDecode{self.uuid} buf\n"),
                CodeComponent(code.replace("####SHIFT####", str(self.shift))
                                .replace("####UUID####", str(self.uuid)))
            ]
        return module