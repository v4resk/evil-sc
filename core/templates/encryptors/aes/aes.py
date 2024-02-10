from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Aes:
    def __init__(self):
        self.key = None
        self.iv = None
        self.generate_keys()

    def generate_keys(self):
        self.key = get_random_bytes(32)  # 256-bit key
        self.iv = get_random_bytes(16)   # 128-bit IV
    
    def _unpad(self, data):
        pad_byte = data[-1]
        pad_length = pad_byte if isinstance(pad_byte, int) else ord(pad_byte)
        return data[:-pad_length]

    def c_key(self):
        return  ", ".join([f"0x{byte:02x}" for byte in self.key])

    def c_iv(self):
        return ", ".join([f"0x{byte:02x}" for byte in self.iv])

    def encrypt(self, data):
        # PKCS7 padding
        padding_length = AES.block_size - (len(data) % AES.block_size)
        padded_data = data + bytes([padding_length] * padding_length)

        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        ciphertext = cipher.encrypt(padded_data)
        return ciphertext
    
    def decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return decrypted_data.rstrip(b'\0')  # Remove padding
    

