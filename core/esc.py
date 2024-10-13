import argparse
import os
from colorama import init, Fore
from core.utils.CustomArgFormatter import CustomArgFormatter
from core.controlers.TemplateLoader import TemplateLoader
from core.controlers.EncryptorsChain import EncryptorsChain
from core.controlers.SandboxEvasionChain import SandboxEvasionChain

def banner():
    init(autoreset=True)

    ascii_art = f"""
    {Fore.CYAN}███████{Fore.GREEN}╗{Fore.CYAN}██{Fore.GREEN}╗   {Fore.CYAN}██{Fore.GREEN}╗{Fore.CYAN}██{Fore.GREEN}╗{Fore.CYAN}██{Fore.GREEN}╗      {Fore.CYAN}███████{Fore.GREEN}╗ {Fore.CYAN}██████{Fore.GREEN}╗
    {Fore.CYAN}██{Fore.GREEN}╔════╝{Fore.CYAN}██{Fore.GREEN}║   {Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}██{Fore.GREEN}║      {Fore.CYAN}██{Fore.GREEN}╔════╝{Fore.CYAN}██{Fore.GREEN}╔════╝
    {Fore.CYAN}█████{Fore.GREEN}╗  {Fore.CYAN}██{Fore.GREEN}║   {Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}█████{Fore.GREEN}╗{Fore.CYAN}███████{Fore.GREEN}╗{Fore.CYAN}██{Fore.GREEN}║     
    {Fore.CYAN}██{Fore.GREEN}╔══╝  ╚{Fore.CYAN}██{Fore.GREEN}╗ {Fore.CYAN}██{Fore.GREEN}╔╝{Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}██{Fore.GREEN}║╚════╝╚════{Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}██{Fore.GREEN}║     
    {Fore.CYAN}███████{Fore.GREEN}╗ ╚{Fore.CYAN}████{Fore.GREEN}╔╝ {Fore.CYAN}██{Fore.GREEN}║{Fore.CYAN}███████{Fore.GREEN}╗ {Fore.CYAN}███████{Fore.GREEN}║╚{Fore.CYAN}██████{Fore.GREEN}╗
    {Fore.GREEN}╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚══════╝ ╚═════╝
    {Fore.CYAN}                                             @v4resk                         
    """

    print(ascii_art)



class esc:
    def __init__(self):
        self.target_process = ""
        self.shellcode_variable = ""
        self.syscall_method = ""
        self.syswhispers_recovery_method = ""
        self.method = ""
        self.encoders = []
        self.encryptors = []
        self.sandbox_evasion = []
        self.evil_sc_template_file = ""
        self.outfile = ""
        self.llvmo = False

        self.valid_encryptors = ["base64","xor","nop","aes","des3","rc4","uuid"]


    def parse_arguments(self):
        # Create the main argument parser
        parser = argparse.ArgumentParser(description='Template-based Shellcode Loader', formatter_class=CustomArgFormatter)

        # Create subparsers for different platforms
        subparsers = parser.add_subparsers(dest='platform', required=True, help='Module to be used')

        # Windows Native subparser
        win_cpp_parser = subparsers.add_parser('windows_cpp', help='Native Windows Shellcode Loader (C++)')

        win_cpp_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_cpp_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_cpp"),
                                help='Shellcode-loading method')

        win_cpp_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_cpp"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_cpp_parser.add_argument('--llvmo', dest='llvmo', action='store_true',
                                help='Use Obfuscator-LLVM to compile')

        #win_cpp_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
        #                        help='Process name for shellcode injection')

        win_cpp_parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                                choices=self.get_available_files("sandboxEvasion", platform="windows_cpp"),
                                help='Sandbox evasion technique')

        win_cpp_parser.add_argument('-sc', '--syscall', dest='syscall_method', default="",
                                choices=["SysWhispers3", "GetSyscallStub"],
                                help='Syscall execution method for supported templates')

        win_cpp_parser.add_argument('--sw-method', dest='syswhispers_recovery_method', default="jumper_randomized",
                                choices=["embedded", "egg_hunter", "jumper", "jumper_randomized"],
                                help='Syscall execution method for supported templates')

        win_cpp_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.exe",
                                help='Output filename')

        #win_cpp_parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
        #                        help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

        # Windows Dotnet subparser
        win_cs_parser = subparsers.add_parser('windows_cs', help='Dotnet Windows Shellcode Loader (C#)')

        win_cs_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_cs_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_cs"),
                                help='Shellcode-loading method')

        win_cs_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_cs"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_cs_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
                                help='Process name for shellcode injection')

        win_cs_parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                                choices=self.get_available_files("sandboxEvasion", platform="windows_cs"),
                                help='Sandbox evasion technique')

        win_cs_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.exe",
                                help='Output filename')

        # Windows Powershell subparser
        win_cs_parser = subparsers.add_parser('windows_pwsh', help='Powershell Windows Shellcode Loader')

        win_cs_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_cs_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_cs"),
                                help='Shellcode-loading method')

        win_cs_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_cs"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_cs_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
                                help='Process name for shellcode injection')

        win_cs_parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                                choices=self.get_available_files("sandboxEvasion", platform="windows_cs"),
                                help='Sandbox evasion technique')

        win_cs_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.exe",
                                help='Output filename')

        #win_cs_parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
        #                        help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

        # Linux subparser (if you want to add specific options for Linux, otherwise can be omitted)
        lin_parser = subparsers.add_parser('linux', help='Linux Shellcode Loader (C++)')
        lin_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        lin_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="linux"),
                                help='Shellcode-loading method')

        lin_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="linux"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        lin_parser.add_argument('-l', '--llvmo', dest='llvmo', action='store_true',
                                help='Use Obfuscator-LLVM to compile')
        
        lin_parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                                choices=self.get_available_files("sandboxEvasion", platform="linux"),
                                help='Sandbox evasion technique')

        #lin_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
        #                        help='Process name for shellcode injection')

        lin_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.elf",
                                help='Output filename')

        #lin_parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
        #                        help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

        # Utils subparser 
        utils_parser = subparsers.add_parser('utils', help='Utility module for shellcodes')
        utils_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        utils_parser.add_argument('-n', '--name', dest='name', default="shellcode",
                                help='Shellcode variable name')

        # Parse arguments
        args = parser.parse_args()

        return args

    # This method return available .cpp files in a given folder, for Menu options
    def get_available_files(self, folder, platform):
        template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', folder, platform)
        if not os.path.exists(template_folder):
            os.makedirs(template_folder)

        available_files = [file[:-4] for file in os.listdir(template_folder) if file.endswith('.esc')]
        
        return available_files


    def run(self):
        # Parsing arguments
        args = self.parse_arguments()
        for key, value in vars(args).items():
            setattr(self, key, value)

        # TO DO
        # SandBox_evasion: Sleep, NoVMenv....
        # SGN Encoder ?
        # Windows Process injection Templates C++/C# 
        # Linux Process injection Templates C++/C#


        #### OUTPUTS  #####
        if self.platform != "utils":

            loader = TemplateLoader(vars(self))

            fields = [
            ("Target OS", self.platform),
            ("Shellcode", self.shellcode_variable),
            ("Methode", os.path.basename(self.method) if self.method else None),
            ("Encryptors", loader.encryptors_chain.to_string()),
            ("Sandbox Evasion", loader.sandboxEvasion_chain.to_string()),
            ("Syscalls", loader.syscall_method),
            ("Compiler", "mono-csc" if self.platform == "windows_cs" else ("LLVM-Obfuscator" if loader.llvmo else "MinGW")),
            ("Output", self.outfile)
            ]

            output = f"{Fore.GREEN}============================================================{Fore.RESET}\n"
            for label, value in fields:
                if value:
                    output += f"{Fore.GREEN}{label:<18}: {Fore.WHITE}{value}{Fore.RESET}\n"
            output += f"{Fore.GREEN}============================================================\n{Fore.RESET}"

            print(output)

            # Run Loader Engine
            
            loader.write_code()
            loader.compile()
    

        else:
            from core.utils.utils import file_to_bytearray,bytearray_to_cpp_sc
            print(f'{Fore.GREEN}Hex Shellcode:\t\t{Fore.WHITE}')
            print(bytearray_to_cpp_sc(file_to_bytearray(self.shellcode_variable,),method=0, sc_var_name=self.name))

            print(f'\n{Fore.GREEN}Array Shellcode:\t\t{Fore.WHITE}')
            print(bytearray_to_cpp_sc(file_to_bytearray(self.shellcode_variable,),method=1, sc_var_name=self.name))
            pass
