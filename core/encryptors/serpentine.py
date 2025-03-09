import secrets
import string
from binascii import hexlify
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.controlers.Module import Module
import uuid

#####
# https://github.com/b-mueller/serpentine
#####

class serpentine(Encryptor):
    def __init__(self, platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        # Generate a 32-byte key using printable characters
        self.key = ''.join(secrets.choice(string.printable) for _ in range(32)).encode()
        self.uuid = uuid.uuid4().hex

    @property
    def c_key(self):
        k = hexlify(self.key).decode()
        return "{" + ",".join([f"0x{k[i:i+2]}" for i in range(0, len(k), 2)]) + "}"

    def encode(self, data):
        if not isinstance(data, (bytes, bytearray)):
            data = data.encode()
        
        # Pad data to multiple of 8 bytes
        padding = 8 - (len(data) % 8) if len(data) % 8 else 0
        data = data + bytes([padding] * padding)
        
        result = bytearray(data)
        key_schedule = self._expand_key()
        
        # Process data in 8-byte blocks
        for i in range(0, len(result), 8):
            block = result[i:i+8]
            for round_key in key_schedule:
                # Apply key
                for j in range(8):
                    block[j] ^= round_key[j]
                # Rotate bits
                for j in range(8):
                    block[j] = ((block[j] << 3) | (block[j] >> 5)) & 0xFF
                # Mix bytes
                for j in range(7):
                    block[j+1] ^= block[j]
            result[i:i+8] = block

        return bytes(result)

    def decode(self, data):
        result = bytearray(data)
        key_schedule = self._expand_key()
        key_schedule.reverse()
        
        for i in range(0, len(result), 8):
            block = result[i:i+8]
            for round_key in key_schedule:
                # Unmix bytes
                for j in range(6, -1, -1):
                    block[j+1] ^= block[j]
                # Rotate bits back
                for j in range(8):
                    block[j] = ((block[j] >> 3) | (block[j] << 5)) & 0xFF
                # Remove key
                for j in range(8):
                    block[j] ^= round_key[j]
            result[i:i+8] = block

        # Remove padding
        if result:
            padding = result[-1]
            if padding < 8:
                result = result[:-padding]

        return bytes(result)

    def _expand_key(self):
        # Generate 16 round keys from the master key
        round_keys = []
        current_key = bytearray(self.key[:8])  # Use first 8 bytes as initial round key
        
        for i in range(16):
            # Generate new round key
            new_key = bytearray(8)
            for j in range(8):
                # Mix with master key bytes
                new_key[j] = current_key[j] ^ self.key[(i*8 + j) % len(self.key)]
                # Add non-linear component
                new_key[j] = ((new_key[j] * 167) + 13) & 0xFF
            
            round_keys.append(bytes(new_key))
            current_key = new_key
            
        return round_keys

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [
                CallComponent(f"length = serpentine_decrypt_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))
                            .replace("####KEY####", self.c_key)),
            ]
        elif self.platform == "windows_cs":
            module.components = [
                CallComponent(f"buf = SerpentineDecrypt_{self.uuid}.Decrypt(buf);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))
                            .replace("####KEY####", self.c_key)),
            ]

        return module