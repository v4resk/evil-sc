# Evil-SC - Template-based Shellcode Loader

## Introduction
Evil-SC is a template-based shellcode loader written in Python. It allows you to generate loader files for injecting shellcode into a target process, using different methods and encoders.

!! WORK IN PROGRESS !!

## Usage
1. Clone the repository:
```bash
git clone https://github.com/your_username/evil-sc.git
cd evil-sc
```

2. Run the script
```
$ python evil-sc.py -h

    ███████╗██╗   ██╗██╗██╗      ███████╗ ██████╗
    ██╔════╝██║   ██║██║██║      ██╔════╝██╔════╝
    █████╗  ██║   ██║██║██║█████╗███████╗██║
    ██╔══╝  ╚██╗ ██╔╝██║██║╚════╝╚════██║██║
    ███████╗ ╚████╔╝ ██║███████╗ ███████║╚██████╗
    ╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚══════╝ ╚═════╝
                                                 @v4resk

usage: evil-sc.py [-h] --method METHOD [--process PROCESS_NAME] [--independent-encoder ENCODER] [--encoder ENCODER] [--sandbox-evasion SANDBOX_EVASION] shellcode

Template-based shellcode loader

positional arguments:
  shellcode             Specify the shellcode variable

options:
  -h, --help            show this help message and exit
  --method METHOD, -m METHOD
                        Specify a method (CreateRemoteThread, ProcessHollowing)
  --process PROCESS_NAME, -p PROCESS_NAME
                        Specify the target process
  --independent-encoder ENCODER, -ie ENCODER
                        Specify a loader-independent encoder (sgn)
  --encoder ENCODER, -e ENCODER
                        Specify a loader-dependent encoder (test-enc, xor)
  --sandbox-evasion SANDBOX_EVASION, -se SANDBOX_EVASION
                        Specify sandbox evasion techniques (sleep)
```

## Resources

There is a lot to come here