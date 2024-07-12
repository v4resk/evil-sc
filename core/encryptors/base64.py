
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent

from core.controlers.Module import Module
from Crypto.Util import strxor # type: ignore
from core.config.config import Config
import uuid

import base64 as base64lib

class base64(Encryptor):
    def __init__(self):
        super().__init__()
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.uuid = uuid.uuid4().hex

    def encode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        return bytearray(base64lib.b64encode(data))

    def decode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        return bytearray(base64lib.b64decode(data))


    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        module.call_component = CallComponent(f"length = base64_decode_{self.uuid}(encoded, length);")
        module.code_components = CodeComponent(code.replace("####UUID####",str(self.uuid)))
        module.include_components = IncludeComponent("<wincrypt.h>")
        module.mingw_options = "-lcrypt32"

        return module

    def test(self):
        print("hello from base64 encryptor object")