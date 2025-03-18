import argparse
import os
from colorama import init, Fore
from core.utils.CustomArgFormatter import CustomArgFormatter
from core.controlers.TemplateLoader import TemplateLoader
from core.controlers.EncryptorsChain import EncryptorsChain
from core.controlers.EvasionChain import EvasionChain

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
        self.shellcode32_variable = ""
        self.syscall_method = ""
        self.syswhispers_recovery_method = ""
        self.method = ""
        self.encoders = []
        self.encryptors = []
        self.evasions = []
        self.evil_sc_template_file = ""
        self.outfile = ""
        self.llvmo = False


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
        
        win_cpp_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="explorer.exe",
                        help='Process name for shellcode injection (use "self" for current process)')

        win_cpp_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_cpp"),
                                help='Evasion module')

        win_cpp_parser.add_argument('-sc', '--syscall', dest='syscall_method', default="",
                                choices=["SysWhispers3", "GetSyscallStub", "NullGate"],
                                help='Syscall execution method for supported templates')

        win_cpp_parser.add_argument('--sw-method', dest='syswhispers_recovery_method', default="jumper_randomized",
                                choices=["embedded", "egg_hunter", "jumper", "jumper_randomized"],
                                help='Syscall recovery method for SysWhispers3 SysWhispers')

        win_cpp_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
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

        win_cs_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_cs"),
                                help='Evasion module')

        win_cs_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')

        # Windows Powershell subparser
        win_pwsh_parser = subparsers.add_parser('windows_pwsh', help='Powershell Windows Shellcode Loader')

        win_pwsh_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_pwsh_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_pwsh"),
                                help='Shellcode-loading method')

        win_pwsh_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_pwsh"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_pwsh_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
                                help='Process name for shellcode injection')
        
        win_pwsh_parser.add_argument( '-c', '--classname', dest='class_name', metavar='CLASS_NAME', default=False,
                                help='Class to be used as EntryPoint (ex: namespace.class)')
        
        win_pwsh_parser.add_argument( '-f', '--function', dest='function_name', metavar='FUNCTION', default=False,
                                help='Function to be used as EntryPoint (ex: Main)')
        
        win_pwsh_parser.add_argument( '-a', '--args', dest='entry_args', metavar='ARGS', default=False,
                                help='Arguments to be used for EntryPoint (ex: "arg1 arg2 arg3")')
  
        win_pwsh_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_pwsh"),
                                help='Evasion module')

        win_pwsh_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')

        #win_cs_parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
        #                        help='Template-independent encoding method to be applied to the shellcode (default: sgn)')


        # Windows VBA (Macro) subparser
        win_vba_parser = subparsers.add_parser('windows_vba', help='Microsoft Office Macros Shellcode Loader (VBA)')

        win_vba_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_vba_parser.add_argument('--x86', metavar='X86_SHELLCODE',dest='shellcode32_variable',
                                help='Specify a raw x86 shellcode file (if template support it)')

        win_vba_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_vba"),
                                help='Shellcode-loading method')

        win_vba_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_vba"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_vba_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="",
                                help='Process name for shellcode injection')

        win_vba_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_vba"),
                                help='Evasion module')

        win_vba_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')

        # Windows JScript subparser
        win_js_parser = subparsers.add_parser('windows_js', help='JScript Windows Shellcode Loader')

        win_js_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_js_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_js"),
                                help='Shellcode-loading method')

        win_js_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_js"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_js_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="",
                                help='Process name for shellcode injection')

        win_js_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_js"),
                                help='Evasion module')

        win_js_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')

        # Windows ASPX subparser
        win_aspx_parser = subparsers.add_parser('windows_aspx', help='Dotnet Windows Shellcode Loader (C#)')

        win_aspx_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_aspx_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_aspx"),
                                help='Shellcode-loading method')

        win_aspx_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_aspx"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_aspx_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="False",
                                help='Process name for shellcode injection')

        win_aspx_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_aspx"),
                                help='Evasion module')

        win_aspx_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')
        
        
        # Linux subparser (if you want to add specific options for Linux, otherwise can be omitted)
        lin_parser = subparsers.add_parser('linux', help='Native Linux Shellcode Loader (C++)')
        lin_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        lin_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="linux"),
                                help='Shellcode-loading method')

        lin_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="linux"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        lin_parser.add_argument('-l', '--llvmo', dest='llvmo', action='store_true',
                                help='Use Obfuscator-LLVM to compile')
        
        lin_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="linux"),
                                help='Evasion module')

        #lin_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
        #                        help='Process name for shellcode injection')

        lin_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
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
        # Obfuscation for .NET & Powershell
        # SandBox_evasion: EKKO Sleep, NoVMenv....
        # AMSI + ETW Patching evasion modules
        # SGN Encoder ?
        # Windows Process injection Templates C++/C# 
        # Linux Process injection Templates C++/C#


        #### OUTPUTS  #####
        if self.platform != "utils":

            self.compiler = "" if self.platform == "windows_pwsh" or self.platform == "windows_vba"  else ("mono-csc" if self.platform == "windows_cs" else ("LLVM-Obfuscator" if self.llvmo else "MinGW"))
            loader = TemplateLoader(vars(self))

            mode = "Injection" if loader.injection else "Execution"
            
            sections = {
                "Inputs": [
                    ("Module", self.platform),
                    ("Input File", self.shellcode_variable),
                    ("x86 Input File", self.shellcode32_variable),
                    ("Input Format", loader.input_file_type.name if loader.input_file_type else None),
                ],
                "Configuration": [
                    ("Mode", mode),
                    ("Method", os.path.basename(self.method) if self.method else None),
                    ("Encryptors", loader.encryptors_chain.to_string()),
                    ("Evasion Modules", loader.evasion_chain.to_string()),
                    ("Injection Process", loader.target_process if mode == "Injection" and loader.target_process else None),
                    ("Syscalls", loader.syscall_method),
                    ("SysWhispers Mode", self.syswhispers_recovery_method if loader.syscall_method == "SysWhispers3" else None),
                    ("Entry Point", loader.class_name),
                    ("Entry Function", loader.function_name),
                    ("Entry Args", loader.entry_args),
                ],
                "Outputs": [
                    ("Compiler", self.compiler),
                    ("Output Format", loader.output_format),
                    ("Output File", f"{self.outfile}{loader.output_format}"),
                ],
            }
        
            # Construct the output string
            output = f"{Fore.GREEN}============================================================{Fore.RESET}\n"
            for section, fields in sections.items():
                output += f"{Fore.CYAN}{section}{Fore.RESET}:\n"
                for label, value in fields:
                    if value:
                        output += f"  {Fore.GREEN}{label:<20}:{Fore.WHITE} {value}{Fore.RESET}\n"
                #output += f"{Fore.GREEN}------------------------------------------------------------{Fore.RESET}\n"
            output += f"{Fore.GREEN}============================================================\n{Fore.RESET}"
        
            # Print the output
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
