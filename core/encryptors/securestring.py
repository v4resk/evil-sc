import os
import base64
import subprocess
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
        # Generate 24 random bytes for the key (valid for AES)
        self.key = os.urandom(24)
        self.uuid = uuid.uuid4().hex
        self.isStringShellcode = True

    def encode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        
        # Format key as PowerShell byte array
        key_str = "(" + ",".join([str(b) for b in self.key]) + ")"
        
        # Create a temporary file with the binary data
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp_file = temp.name
            temp.write(data)
        
        # Create PowerShell command to encrypt the data using SecureString
        # We use a different approach to handle binary data properly
        ps_command = f"""
        # Read binary data as bytes
        $bytes = [System.IO.File]::ReadAllBytes("{temp_file}")
        
        # Convert bytes to Base64 string (to preserve binary data)
        $base64String = [Convert]::ToBase64String($bytes)
        
        # Create SecureString from the Base64 string
        $secureString = ConvertTo-SecureString $base64String -AsPlainText -Force
        
        # Encrypt the SecureString with our key
        $encryptedString = ConvertFrom-SecureString -SecureString $secureString -Key {key_str}
        
        Write-Output $encryptedString
        """
        
        # Execute PowerShell command and capture output
        try:
            import subprocess
            result = subprocess.run(
                ["pwsh", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Get the encrypted output
            encrypted_string = result.stdout.strip()
            
            # Clean up temporary file
            import os
            os.unlink(temp_file)
            
            return bytearray(encrypted_string.encode('utf-8'))
        except subprocess.CalledProcessError as e:
            import os
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            raise Exception(f"PowerShell encryption failed: {e.stderr}")

    def decode(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        return bytearray(data)

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