####################
# This funcion take a file_path and convert it to a C/C++ code format
# This is a "xxd -i" like function in python
####################
import os

def file_to_bytearray(filepath):
    with open(filepath, 'rb') as file:
        byte_array_data = bytearray(file.read())
    return byte_array_data

def file_to_cpp_sc(file_path, sc_var_name="shellcode"):
    with open(file_path, 'rb') as file:
        data = file.read()

    hex_string = ''.join([format(byte, '02x') for byte in data])

    output = f"unsigned char {sc_var_name}[] = \n\"\\x"
    output += '\\x'.join([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])
    output += "\";"

    return output


def bytearray_to_cpp_sc(sc_bytearray,sc_var_name="shellcode", method=0):

    if method == 0:
        hex_string = ''.join([format(byte, '02x') for byte in sc_bytearray])

        output = f"unsigned char {sc_var_name}[] = \n\"\\x"
        output += '\\x'.join([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])
        output += "\";"
        return output
    
    if method == 1:
         return  f"unsigned char {sc_var_name}[] = \n{{" + ", ".join([f"0x{byte:02x}" for byte in sc_bytearray]) + "};"
