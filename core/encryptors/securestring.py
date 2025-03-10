import os
import base64
from core.encryptors.Encryptor import Encryptor
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.controlers.Module import Module
import uuid

class securestring(Encryptor):
    def __init__(self, platform):
        super().__init__(platform)
        self.decoder_in = [bytes]
        self.decoder_out = [bytes]
        # Generate 24 random bytes for the key
        self.key = os.urandom(24)
        self.uuid = uuid.uuid4().hex
        self.isStringShellcode = True

    def encode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        
        # Base64 encode the binary data first to make it safe for PowerShell
        # Format key as PowerShell byte array
        key_str = "(" + ",".join([str(b) for b in self.key]) + ")"
        data_str = "(" + ",".join([str(b) for b in data]) + ")"
        print(key_str)
        # Create PowerShell command to encrypt the data using SecureString
        ps_command = f"""
        $Data = [System.Text.Encoding]::UTF8.GetString({data_str})
        ConvertFrom-SecureString (ConvertTo-SecureString $Data -Force -AsPlainText) -Key {key_str}
        """
        
        # Execute PowerShell command and capture output
        import subprocess
        try:
            result = subprocess.run(
                ["pwsh", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Get the encrypted output (already base64 encoded)
            encrypted_base64 = result.stdout.strip()
            
            return bytearray(encrypted_base64.encode('utf-8'))
        except subprocess.CalledProcessError as e:
            raise Exception(f"PowerShell encryption failed: {e.stderr}")

    def decode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        return bytearray(base64.b64decode(data))

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_pwsh":
            # Format key as PowerShell byte array
            key_str = "@(" + ",".join([str(b) for b in self.key]) + ")"
            
            module.components = [
                CallComponent(f"$buf = Invoke-SecureStringDecrypt_{self.uuid} -Data $buf\n"),
                CodeComponent(code.replace("####UUID####", str(self.uuid))
                                .replace("####KEY####", key_str))
            ]

        return module