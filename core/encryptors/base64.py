
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.controlers.Module import Module
import uuid

import base64 as base64lib

class base64(Encryptor):
    def __init__(self,platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.uuid = uuid.uuid4().hex
        self.isStringShellcode = False if self.platform == "windows_cs" else True


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

        if self.platform == "windows_cpp":
            module.components = [
                CallComponent(f"length = base64_decode_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))),
                IncludeComponent("<wincrypt.h>")
            ]
            module.mingw_options = "-lcrypt32 "
        
        elif self.platform == "windows_cs":
            module.components = [
                CallComponent(f"buf = Base64Encoder_{self.uuid}.Decode(buf);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))),
            ]

        elif self.platform == "windows_pwsh":
            module.components = [
                CallComponent(f"$buf = Invoke-Base64Decode{self.uuid} -Data $buf\n"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))),
            ]
        return module

    def test(self):
        print("hello from base64 encryptor object")