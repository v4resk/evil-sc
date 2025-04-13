from binascii import hexlify
from core.config.config import Config
import base64
from core.utils.enums.inputType import inputType
from core.utils.utils import verify_file_type
import random
import string

debug_mode = Config().get("DEBUG", "SHELLCODE")   

class ShellcodeControler:
    def __init__(self, shellcode_variable, encryptors_chain, platform):
        self.encryptors_chain = encryptors_chain
        self.platform = platform
        
        # Check if input is text command
        if isinstance(shellcode_variable, str) and verify_file_type(shellcode_variable) == inputType.TEXT:
            self.shellcode_bytes = bytes(shellcode_variable, 'utf-8')
        else:
            self.shellcode_bytes = self.file_to_bytes(shellcode_variable)
        
        self.encrypted_shellcode_bytes = self.encrypt_shellcode()
        self.chain_ending_w_str = self.check_str_encryptors()
        self.shellcode_len = len(self.encrypted_shellcode_bytes)


    def file_to_bytes(self,filepath):
        with open(filepath, 'rb') as file:
            byte_array_data = bytes(file.read())
        return byte_array_data

    def encrypt_shellcode(self):
        i = 0
        encrypted_shellcode_bytes = self.shellcode_bytes 
        for key, encryptor in reversed(self.encryptors_chain.chain.items()):
            
            ### DEBUG ####
            if debug_mode == "True":
                print(f"{encryptor.to_string()}{i} Before Encode: {self.get_shellcode()}")
                print()

            encrypted_shellcode_bytes = encryptor.encode(encrypted_shellcode_bytes)

            ### DEBUG ####
            if debug_mode == "True":
                print(f"{encryptor.to_string()} n°{i} After Encode: {self.get_shellcode()}")
                print()
                i = i+1
        return encrypted_shellcode_bytes


    
    def check_str_encryptors(self):
        if len(self.encryptors_chain.chain.items()) == 0:
            return False
        for key, encryptor in self.encryptors_chain.chain.items():
            if not encryptor.isStringShellcode:
                return False
            else:
                return True
            break

    
    def get_encrypted_shellcode_len(self):
        if self.chain_ending_w_str is False:
            return self.shellcode_len
        else:
            return self.shellcode_len + 2

    def get_encrypted_shellcode_c(self):
        #return shellcode
        # Check if some enc should be returned as "String" format
        if not self.chain_ending_w_str:
            return self.get_shellcode(self.encrypted_shellcode_bytes)
        else:
            print("[*] String shellcode")
            #return self.get_shellcode(encrypted_shellcode_bytes)
            return "\"" +self.encrypted_shellcode_bytes.decode("utf-8")+"\""




    def get_encrypted_shellcode_pwsh(self):
        return self.get_shellcode(self.encrypted_shellcode_bytes, format="pwsh")
     


    def get_shellcode(self):
        if self.platform == "windows_cpp" or self.platform == "windows_aspx" or self.platform == "linux":
            if self.chain_ending_w_str is False:
                shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
                shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
                return shellcode
            else:
                print("[*] String shellcode")
                return "\"" +self.encrypted_shellcode_bytes.decode("utf-8")+"\\0"+"\""
            
        if self.platform == "windows_cs":
            if self.chain_ending_w_str is False:
                shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
                shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
                return shellcode
            else:
                print("[*] String shellcode")
                shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
                shellcode = "{" + ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)]) + "}"
                return shellcode+";System.Text.Encoding.ASCII.GetBytes(\"" +self.encrypted_shellcode_bytes.decode("utf-8")+"\\0"+"\").CopyTo(buf, 0)"        

        
        elif self.platform == "windows_pwsh":
            if self.chain_ending_w_str is False:
                shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
                shellcode = ",".join([f"0x{shellcode[i:i + 2]}" for i in range(0, len(shellcode), 2)])
                shellcode = f"[Byte[]] ({shellcode})"
                return shellcode
            else:
                print("[*] String shellcode")
                return f"\"{self.encrypted_shellcode_bytes.decode('utf-8')}\""
    
        elif self.platform == "windows_vba" or self.platform == "windows_vbs":
            shellcode = hexlify(self.encrypted_shellcode_bytes).decode()
            byte_array = [f"{int(shellcode[i:i + 2], 16)}" for i in range(0, len(shellcode), 2)]

            # Split into lines while respecting the VBA line length limitation
            max_line_length = 350  # Maximum length per line before needing a line continuation
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
        
        elif self.platform == "windows_js":
            shellcode = base64.b64encode(self.encrypted_shellcode_bytes)
            shellcode = shellcode.decode(encoding="latin-1")
            return f"\"{shellcode}\""
        
    def get_shellcode_type(self):
        """
        Returns the appropriate shellcode type declaration based on platform and encoding chain
        """
        if self.platform == "windows_pwsh":
            if self.chain_ending_w_str:
                return " "
            else:
                return "[Byte[]]"
        elif self.platform == "windows_cs" or self.platform == "windows_aspx":
            if self.chain_ending_w_str:
                return "string"
            else:
                return "byte[]"
        elif self.platform == "windows_cpp":
            if self.chain_ending_w_str:
                return "char*"
            else:
                return "unsigned char*"
        elif self.platform == "linux":
            if self.chain_ending_w_str:
                return "char*"
            else:
                return "unsigned char*"
        else:
            # Default case
            return "byte[]"
    
    
    def generate_customxml(self):
        part_name = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
        step = 512
        customxml = ''
        part_number = 1
        encoded = base64.b64encode(self.encrypted_shellcode_bytes).decode()
        for i in range(0, len(encoded), step):
            customxml += '<{0}_{1}>{2}</{0}_{1}>\n'.format(part_name, part_number, encoded[i:i+step])
            part_number += 1

        return '<{0}_0>\n{1}</{0}_0>'.format(part_name, customxml), part_name