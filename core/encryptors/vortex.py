import secrets
import string
from binascii import hexlify
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.controlers.Module import Module
import uuid

#####
# Stream cipher implementation with counter mode (CTR) that:
# - Uses 16-byte (128-bit) blocks with PKCS7 padding
# - Employs a 32-byte key and 16-byte nonce for encryption
# - Operates as a stream cipher by:
#   1. Using nonce as an incrementing counter
#   2. Generating keystream blocks through key-dependent transformations:
#      - Bit rotations
#      - Key addition
#      - Bit mixing
#   3. XORing keystream with plaintext
# - Counter mode makes it parallelizable and allows random access
# - Supports both Windows C++ and C# implementations
#
# Note: This is a custom stream cipher implementation for educational/research purposes.
# For production security, use standard cryptographic algorithms (e.g., ChaCha20, AES-CTR).
#####

class vortex(Encryptor):
    def __init__(self, platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        # 32-byte key and 16-byte nonce
        self.key = ''.join(secrets.choice(string.printable) for _ in range(32)).encode()
        self.nonce = secrets.token_bytes(16)
        self.uuid = uuid.uuid4().hex

    @property
    def c_key(self):
        k = hexlify(self.key).decode()
        return "{" + ",".join([f"0x{k[i:i+2]}" for i in range(0, len(k), 2)]) + "}"

    @property
    def c_nonce(self):
        n = hexlify(self.nonce).decode()
        return "{" + ",".join([f"0x{n[i:i+2]}" for i in range(0, len(n), 2)]) + "}"

    def encode(self, data):
        if not isinstance(data, (bytes, bytearray)):
            data = data.encode()
        
        # Pad data to multiple of 16 bytes
        padding = 16 - (len(data) % 16) if len(data) % 16 else 0
        data = data + bytes([padding] * padding)
        
        result = bytearray(data)
        counter = bytearray(self.nonce)  # Use nonce as initial counter
        
        # Process data in 16-byte blocks
        for i in range(0, len(result), 16):
            # Generate keystream block
            keystream = self._generate_keystream(counter)
            
            # XOR data with keystream
            for j in range(16):
                result[i + j] ^= keystream[j]
            
            # Increment counter
            for j in range(15, -1, -1):
                counter[j] = (counter[j] + 1) & 0xFF
                if counter[j] != 0:
                    break
        
        return bytes(result)

    def decode(self, data):
        # Decryption is identical to encryption due to XOR properties
        result = bytearray(self.encode(data))
        
        # Remove padding
        if result:
            padding = result[-1]
            if padding <= 16:
                result = result[:-padding]
        
        return bytes(result)

    def _generate_keystream(self, counter):
        # Mix counter with key to generate keystream
        result = bytearray(16)
        for i in range(16):
            x = counter[i]
            # Apply key-dependent transformations
            for j in range(8):
                k = self.key[(i * 8 + j) % len(self.key)]
                x = ((x << 1) | (x >> 7)) & 0xFF  # rotate left
                x = (x + k) & 0xFF                # add key byte
                x ^= ((x << 4) | (x >> 4)) & 0xFF # mix bits
            result[i] = x
        return result

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [
                CallComponent(f"length = vortex_decrypt_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))
                            .replace("####KEY####", self.c_key)
                            .replace("####NONCE####", self.c_nonce)),
            ]
        elif self.platform == "windows_cs":
            module.components = [
                CallComponent(f"buf = VortexDecrypt_{self.uuid}.Decrypt(buf);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))
                            .replace("####KEY####", self.c_key)
                            .replace("####NONCE####", self.c_nonce)),
            ]

        return module