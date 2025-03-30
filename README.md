# Evil-SC - Template-based Shellcode Loader

## Introduction

Evil-SC is a template-based shellcode loader written in Python. It allows you to generate loader files for shellcode execution and injection across multiple platforms and languages. The tool supports:

- **Multiple Platforms Support**: Windows (C++, C#, PowerShell, VBA, JavaScript) and Linux (C++)
- **Direct & Indirect Syscalls**: [SysWhispers3](https://github.com/klezVirus/SysWhispers3), [GetSyscallStub](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time) for Direct Syscall and [NullGate](https://github.com/0xsch1zo/NullGate) for Indirect Syscalls
- **Chained Encryption**: Multiple encryption algorithms can be chained
- **Chained Evasion Techniques**: Various sandbox evasion methods that can be chained 
- **Process Injection**: Different injection and execution techniques (QueuAPC, )
- **Obfuscation**: LLVM-based code obfuscation
 
> WORK IN PROGRESS !


## Supported Features by Platform

### Encryption/Encoding Options

| Encoder | Windows C++ | Windows C# | PowerShell | VBA | JavaScript | Windows ASPX | Linux C++ |
|---------|-------------|------------|------------|-----|------------|--------------|-----------|
| XOR | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| AES | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| RC4 | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| Base64 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| UUID | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Serpentine* | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Vortex* | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| DES3 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| NOP | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Custom AES* (aesc) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Custom Base64* (base64c) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Custom RC4* (rc4c) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |

> **Note**: Entries marked with an asterisk (*) are custom implementations that do not rely on native cryptographic functions. These implementations re-implement the cryptographic logic from scratch to avoid detection based on API calls to cryptographic libraries.

### Syscall Types Support

| Syscall Type | Windows C++ | Windows C# | PowerShell | VBA | JavaScript | Windows ASPX | Linux C++ |
|--------------|-------------|------------|------------|-----|------------|--------------|-----------|
| Direct (SysWhispers3) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Direct (GetSyscallStub) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Indirect (NullGate) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Standard API | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |


### Evasion Techniques

| Evasion Technique | Windows C++ | Windows C# | PowerShell | VBA | JavaScript | Windows ASPX | Linux C++ |
|-------------------|-------------|------------|------------|-----|------------|--------------|-----------|
| Sleep Evasion | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| AMSI Bypass | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ |
| ETW Bypass | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Memory Scanning | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Sandbox Detection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Process Checking | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Domain Checking | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Username Checking | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk Size Checking | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Memory Size Checking | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| DLL Unhooking | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

### Execution/Injection Methods

- **Windows C++**: CreateThread, CreateLocalThread, CreateRemoteThread, QueueUserAPC, CreateFiber, ThreadPoolCallBack, VectoredHandler, WndProc, LocalModuleStomping, RemoteModuleStomping, Exec

- **Windows C#**: CreateThread, CreateRemoteThread, QueueUserAPC

- **PowerShell**: Reflection, DelegateType, PowerInject, PowerHollow, Exec

- **VBA**: Runner, Inject

- **Windows JavaScript**: VenomaToJs

- **Windows ASPX**: CreateThread, CreateRemoteThread, NtMapViewOfSection

- **Linux C++**: SimpleExec, Pthread, LD_PRELOAD, LD_LIBRARY_PATH

## Installation

```bash
# Install dependencies
sudo apt update
sudo apt install mono-complete mingw-w64 powershell

# Install the repo
git clone https://github.com/yourusername/Evil-SC.git
cd Evil-SC

python -m virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

The tool uses a platform-based command structure. First, you select the platform and language, then specify the options for that platform.

```bash
python evil-sc.py --help
```

### Available Platforms

- `windows_cpp` - Windows C++ loader
- `windows_cs` - Windows C# loader
- `windows_pwsh` - Windows PowerShell loader
- `windows_vba` - Windows VBA (Office Macros) loader
- `windows_js` - Windows JavaScript loader
- `windows_aspx` - Windows ASPX loader
- `linux` - Linux C++ loader
- `utils` - Utility functions for shellcode

### Basic Examples

```bash
# Generate a Windows C++ loader with XOR encryption
python evil-sc.py windows_cpp msf.raw -m CreateLocalThread -e xor -o loader

# Generate a Windows C++ loader with QueueUserAPC method and GetSyscallStub syscalls
python evil-sc.py windows_cpp msf.raw -m QueueUserAPC -e xor -sc GetSyscallStub -o loader

# Generate a PowerShell loader with AES encryption and sleep evasion
python evil-sc.py windows_pwsh msf.raw -m exec -e aes -em sleep -o loader

# Generate a Linux C++ loader with RC4 encryption
python evil-sc.py linux msf.raw -m pthread -e rc4 -o loader
```

### Advanced Examples

```bash
# Chain multiple encryption methods and use process injection
python evil-sc.py windows_cpp msf.raw -m CreateRemoteThread -e xor -e aes -e base64 -p explorer.exe -o advanced_loader

# Use custom encryptors and SysWhispers3 Direct Syscalls in jumper_randomized mode
python evil-sc.py windows_cpp msf.raw -m CreateFiber -e aesc -e serpentine -sc SysWhispers3 --sw-method jumper_randomized -em sleep -o stealthy_loader

# Generate a VBA macro with AES encryption
python evil-sc.py windows_vba msf.raw -m exec -e aes -o macro_loader

# Use LLVM obfuscation for C++ loader
python evil-sc.py windows_cpp msf.raw -m CreateLocalThread -e xor --llvmo -o obfuscated_loader
```

### Command Line Options

Each platform has its own set of options. Here's an example for Windows C++:

```
-m, --method            Shellcode-loading method
-e, --encrypt           Encryption/Encoding algorithm (can be specified multiple times for chaining)
--llvmo                 Use Obfuscator-LLVM to compile
-p, --process           Process name for shellcode injection (use "self" for current process)
-em, --evasion-module   Evasion module (can be specified multiple times)
-sc, --syscall          Syscall execution method (SysWhispers3, GetSyscallStub, NullGate)
--sw-method             Syscall recovery method for SysWhispers3
-o, --outfile           Output filename
```

## Known Issues & Planned Features

- **BUG:** SecureString is not supported for PowerShell if after an other encryption method (AES mainly)
- **FEATURE:** Support for Assembly Execution inside a C# Template
- **FEATURE:** Support for DLL copy (for DLL sideloading)  
- **FEATURE:** Obfusaction modules (after compile / generation)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and research purposes only. The author is not responsible for any misuse or damage caused by this program. Always use responsibly and ethically.

## Resources

- [Inceptor](https://github.com/klezVirus/inceptor) for the initial idea and architecture of the project
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3) for direct syscalls support
- [GetSyscallStub](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time) for direct syscalls support
- [NullGate](https://github.com/0xsch1zo/NullGate) for indirect syscalls support
