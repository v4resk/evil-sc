
import secrets
import string

from binascii import hexlify

from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
import uuid

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class aes(Encryptor):
    def __init__(self,platform):
        super().__init__(platform)
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
    
    @property
    def pwsh_key(self):
        return "@(" + ",".join([str(b) for b in self.key]) + ")"
    
    @property
    def c_iv_pwsh(self):
        return "@(" + ",".join([str(b) for b in self.iv]) + ")"
    
    @property
    def vba_iv(self):
        k = hexlify(self.iv).decode()
        byte_array = [f"{int(k[i:i + 2], 16)}" for i in range(0, len(k), 2)]
        max_line_length = 75  # Maximum length per line before needing a line continuation
        lines = []
        current_line = "Array("
        for byte in byte_array:
            # Check if adding the byte would exceed the max length
            if len(current_line) + len(byte) + 1 > max_line_length:  # +1 for the comma
                current_line = current_line.rstrip(',') + " _"  # Trim last comma and add continuation
                lines.append(current_line)  # Append the current line
                current_line = " " * 8 + byte + ", "  # Start a new line with indentation
            else:
                current_line += byte + ", "
        # Add the final line and ensure proper formatting
        current_line = current_line.rstrip(', ') + ")"
        lines.append(current_line)
        return "\n".join(lines)  # Join all lines into a single output


    @property
    def vba_key(self):
        k = hexlify(self.iv).decode()
        byte_array = [f"{int(k[i:i + 2], 16)}" for i in range(0, len(k), 2)]
        max_line_length = 75  # Maximum length per line before needing a line continuation
        lines = []
        current_line = "Array("
        for byte in byte_array:
            # Check if adding the byte would exceed the max length
            if len(current_line) + len(byte) + 1 > max_line_length:  # +1 for the comma
                current_line = current_line.rstrip(',') + " _"  # Trim last comma and add continuation
                lines.append(current_line)  # Append the current line
                current_line = " " * 8 + byte + ", "  # Start a new line with indentation
            else:
                current_line += byte + ", "
        # Add the final line and ensure proper formatting
        current_line = current_line.rstrip(', ') + ")"
        lines.append(current_line)
        return "\n".join(lines)  # Join all lines into a single output



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

        if self.platform == "windows_cpp":
            module.components = [
                CallComponent(f"length = aes_decrypt_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.c_key).replace("####IV####", self.c_iv)),
                IncludeComponent("#include <bcrypt.h>")
            ]
            module.mingw_options = "-lbcrypt "
        
        elif self.platform == "windows_cs":
            module.components = [
                DefineComponent("using System.Security.Cryptography;\n"),
                DefineComponent("using System.IO;\n"),
                CallComponent(f"buf = AesEncryptor_{self.uuid}.Decrypt(buf);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.key.decode()).replace("####SALT####", self.salt.decode())),
                
            ]
        elif self.platform == "windows_aspx":
            module.components = [
                IncludeComponent("<%@ Import Namespace=\"System.Security.Cryptography\" %>\n"),
                IncludeComponent("<%@ Import Namespace=\"System.IO\" %>\n"),
                CallComponent(f"buf = AesEncryptor_{self.uuid}.Decrypt(buf);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.key.decode()).replace("####SALT####", self.salt.decode())),
                
            ]
        elif self.platform == "windows_pwsh":
            module.components = [
                CallComponent(f"$buf = Invoke-AesDecrypt_{self.uuid} -Data $buf\n"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.key.decode()).replace("####SALT####", self.salt.decode())),
                
            ]
        
        elif self.platform == "windows_vba":
            module.components = [
                CallComponent(f"AESDecrypt{self.uuid} buf\n"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.key.hex()).replace("####IV####", self.iv.hex())),
                DefineComponent("""
Private Declare PtrSafe Function CryptAcquireContext Lib "advapi32.dll" Alias "CryptAcquireContextA" (phProv As LongPtr, ByVal pszContainer As String, ByVal pszProvider As String, ByVal dwProvType As LongPtr, ByVal dwFlags As LongPtr) As Boolean
Private Declare PtrSafe Function CryptReleaseContext Lib "advapi32.dll" (ByVal hProv As LongPtr, ByVal dwFlags As LongPtr) As Boolean
Private Declare PtrSafe Function CryptCreateHash Lib "advapi32.dll" (ByVal hProv As LongPtr, ByVal Algid As Long, ByVal hKey As LongPtr, ByVal dwFlags As LongPtr, phHash As LongPtr) As Boolean
Private Declare PtrSafe Function CryptHashData Lib "advapi32.dll" (ByVal hHash As LongPtr, pbData As Any, ByVal dwDataLen As LongPtr, ByVal dwFlags As LongPtr) As Boolean
Private Declare PtrSafe Function CryptDeriveKey Lib "advapi32.dll" (ByVal hProv As LongPtr, ByVal Algid As Long, ByVal hBaseData As LongPtr, ByVal dwFlags As LongPtr, phKey As LongPtr) As Boolean
Private Declare PtrSafe Function CryptDecrypt Lib "advapi32.dll" (ByVal hKey As LongPtr, ByVal hHash As LongPtr, ByVal Final As Boolean, ByVal dwFlags As LongPtr, pbData As Any, pdwDataLen As LongPtr) As Boolean
""")
            ]            
            
            
        elif self.platform == "linux":
            module.components = [
                CallComponent(f"length = aes_decrypt_{self.uuid}(encoded, length);"),
                CodeComponent(code.replace("####UUID####",str(self.uuid)).replace("####KEY####", self.c_key).replace("####IV####", self.c_iv)),
                IncludeComponent("#include <openssl/evp.h>"),
                IncludeComponent("#include <openssl/err.h>")
            ]
            # Specify the correct linker flags for OpenSSL
            module.mingw_options = " -lssl -lcrypto"

        return module