####################
# This funcion take a file_path and convert it to a C/C++ code format
# This is a "xxd -i" like function in python
####################
import os
import subprocess
import hashlib
import math
from pathlib import Path
from pefile import PE,PEFormatError
from core.utils.enums.inputType import inputType
from colorama import init, Fore
import pefile
import re

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
        # If input is a string without file extension or looks like a command, treat it as TEXT
        if isinstance(filename, str) and ('.' not in filename or ' ' in filename):
            return inputType.TEXT

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
        except FileNotFoundError:
            # If file doesn't exist and input looks like a command, treat as TEXT
            return inputType.TEXT
        
def calculate_shannon_entropy(data: bytes) -> float:
    """
    CREDIT: https://gitlab.com/KevinJClark/ek47
    Calculate the Shannon entropy value of the given data.

    The Shannon entropy measures the amount of uncertainty or information contained in a set of data.
    The result will be between 0.000 and 8.000.

    Args:
        data (bytes): The input data for entropy calculation.

    Returns:
        float: The calculated Shannon entropy value.

    References:
        - Original code: https://github.com/stanislavkozlovski/python_exercises/blob/master/easy_263_calculate_shannon_entropy.py
        - Stack Overflow: https://stackoverflow.com/questions/6256437/entropy-in-binary-files-whats-the-purpose
    """
    probability = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in probability])
    return round(entropy, 3)


def sha256sum(output_file) -> str:
    hasher = hashlib.sha256()
    with open(output_file, "rb") as fd:
        for byte_block in iter(lambda: fd.read(4096), b""):
            hasher.update(byte_block)
    hash_value = hasher.hexdigest()
    return f'{Fore.GREEN}[+]{Fore.WHITE} Sha256sum:\t{hash_value}{Fore.RESET}'

def entropy(output_file) -> str:
    with open(output_file, 'rb') as fd:
        entropy_value = calculate_shannon_entropy(fd.read())
        prefix = f'{Fore.GREEN}[+]' if entropy_value < 5.5 else f'{Fore.RED}[-]'
        return f'{prefix}{Fore.WHITE} Entropy:\t{entropy_value:.3f} / 8.000{Fore.RESET}'

def size(output_file) -> str:
    """Return the given bytes as a human friendly KB, MB, GB, or TB string."""
    B = float(os.path.getsize(output_file))
    KB = float(1024)
    MB = float(KB ** 2) # 1,048,576
    GB = float(KB ** 3) # 1,073,741,824
    TB = float(KB ** 4) # 1,099,511,627,776

    if B < KB:
        size_str = '{0} {1}'.format(B,'Bytes' if 0 == B > 1 else 'Byte')
    elif KB <= B < MB:
        size_str = '{0:.2f} KB'.format(B / KB)
    elif MB <= B < GB:
        size_str = '{0:.2f} MB'.format(B / MB)
    elif GB <= B < TB:
        size_str = '{0:.2f} GB'.format(B / GB)
    elif TB <= B:
        size_str = '{0:.2f} TB'.format(B / TB)
    
    return f'{Fore.GREEN}[+]{Fore.WHITE} Size:\t{size_str}{Fore.RESET}'


