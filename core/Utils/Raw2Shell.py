####################
# This funcion take a file_path and convert it to a C/C++ code format
# This is a "xxd -i" like function in python
####################
import os

def raw2shell(file_path):
    file_name, _ = os.path.splitext(os.path.basename(file_path))
    
    with open(file_path, 'rb') as file:
        data = file.read()

    hex_string = ''.join([format(byte, '02x') for byte in data])

    output = f"unsigned char shellcode[] = {{\n"
    output += ', '.join([f'0x{hex_string[i:i+2]}' for i in range(0, len(hex_string), 2)])
    output += "};"

    return output