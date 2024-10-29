####################
# This funcion take a file_path and convert it to a C/C++ code format
# This is a "xxd -i" like function in python
####################
import os
import subprocess
from pathlib import Path
from pefile import PE,PEFormatError
from core.utils.enums.inputType import inputType

def get_project_root() -> Path:
    return Path(__file__).parent.parent

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
    sc_size = len(sc_bytearray)
    if method == 0:
        hex_string = ''.join([format(byte, '02x') for byte in sc_bytearray])

        output = f"unsigned char {sc_var_name}[{sc_size}] = \n\"\\x"
        output += '\\x'.join([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])
        output += "\";"
        return output
    
    if method == 1:
         return  f"unsigned char {sc_var_name}[{sc_size}] = \n{{" + ", ".join([f"0x{byte:02x}" for byte in sc_bytearray]) + "};"



def isDotNet(filename):
        try:
            pe = PE(filename)
            clr_metadata = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            return not (clr_metadata.VirtualAddress == 0 and clr_metadata.Size == 0)
        except PEFormatError:
            return False

def verify_file_type(filename):
        try:
            pe = PE(filename)
            is_dotnet = isDotNet(filename)

            # Determine if the file is a DLL
            is_dll = (pe.FILE_HEADER.Characteristics & 0x2000) != 0

            if is_dotnet:
                return inputType.DOTNET_DLL if is_dll else inputType.DOTNET_BIN
            else:
                return inputType.NATIVE_DLL if is_dll else inputType.NATIVE_BIN

        except PEFormatError:
            # If not a valid PE file, consider it a raw binary
            return inputType.RAW_BIN