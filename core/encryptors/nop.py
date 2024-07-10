
from binascii import hexlify, unhexlify

from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent

from core.controlers.Module import Module
from Crypto.Util import strxor # type: ignore
from core.config.config import Config
import uuid


class nop(Encryptor):
    """
    This encoder takes as input an hexlified version of the payload
    Then, it perform a NOP insertion byte per byte
    The resulting payload is duplicated in size

    Input String
    Output String
    """

    def __init__(self):
        super().__init__()
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        self.uuid = uuid.uuid4().hex

    def encode(self, data):
        if isinstance(data, bytes):
            data = hexlify(data).decode()
        data = "".join([f"{data[i:i + 2]}90" for i in range(0, len(data), 2)])
        return unhexlify(data)

    def decode(self, data):
        if isinstance(data, bytes):
            data = hexlify(data).decode()
        decoded = ""
        tokens = [data[i:i + 2] for i in range(0, len(data), 2)]
        for i in range(len(tokens)):
            if i % 2 == 0:
                decoded += tokens[i]
        return unhexlify(decoded)


    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        module.call_component = CallComponent(f"length = nop_decode_{self.uuid}(encoded, length);")
        module.code_components = CodeComponent(code.replace("####UUID####",str(self.uuid)))

        return module

    def test(self):
        print("hello from nop encryptor object")