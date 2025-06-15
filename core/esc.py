import argparse
import os
from colorama import init, Fore
from core.utils.CustomArgFormatter import CustomArgFormatter
from core.controlers.TemplateLoader import TemplateLoader
from core.controlers.EncryptorsChain import EncryptorsChain
from core.controlers.EvasionChain import EvasionChain
from core.utils.utils import sha256sum, entropy, size
from core.utils.office_utils import insert_custom_xml, list_custom_xml

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
        self.dot2js_version = ""
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

        win_cpp_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions', metavar='EVASION[:ARGS]', 
                                   help=f'Evasion module (e.g., sleep or sleep:10). Available: {", ".join(self.get_available_files("evasions", platform="windows_cpp"))}')

        win_cpp_parser.add_argument('-sc', '--syscall', dest='syscall_method', default="",
                                choices=["SysWhispers3", "GetSyscallStub", "NullGate"],
                                help='Syscall execution method for supported templates')

        win_cpp_parser.add_argument('--sw-method', dest='syswhispers_recovery_method', default="jumper_randomized",
                                choices=["embedded", "egg_hunter", "jumper", "jumper_randomized"],
                                help='Syscall recovery method for SysWhispers3 SysWhispers. Default: jumper_randomized')

        win_cpp_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')
        
        win_cpp_parser.add_argument('-a', '--arch', dest='arch', metavar='ARCH', default="x64",
                                help='Target architecture (x86 or x64). Default: x64')

        # Windows Dotnet subparser
        win_cs_parser = subparsers.add_parser('windows_cs', help='Dotnet Windows Shellcode Loader (C#)')

        win_cs_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_cs_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_cs"),
                                help='Shellcode-loading method')

        win_cs_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_cs"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_cs_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="notepad.exe",
                        help='Process name for shellcode injection (use "self" for current process)')

        win_cs_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions', metavar='EVASION[:ARGS]', 
                                   help=f'Evasion module (e.g., sleep or sleep:10). Available: {", ".join(self.get_available_files("evasions", platform="windows_cs"))}')

        win_cs_parser.add_argument( '-c', '--classname', dest='class_name', metavar='CLASS_NAME', default=False,
                                help='Class to be used as EntryPoint (ex: namespace.class)')
        
        win_cs_parser.add_argument( '-f', '--function', dest='function_name', metavar='FUNCTION', default=False,
                                help='Function to be used as EntryPoint (ex: Main)')
        
        win_cs_parser.add_argument( '--args', dest='entry_args', metavar='ARGS', default=False,
                                help='Arguments to be used for EntryPoint (ex: "arg1 arg2 arg3")')

        win_cs_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')
        
        win_cs_parser.add_argument('-a', '--arch', dest='arch', metavar='ARCH', default="x64",
                                help='Target architecture (x86 or x64)')
        # Add this after the existing win_cs_parser arguments (around line 94)
        win_cs_parser.add_argument('--dotnetver', dest='dotnet_version', default="4",
                          choices=["2", "4"], metavar='VERSION',
                          help='Target .NET Framework version (2 or 4). Default: 4')

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
        
        win_pwsh_parser.add_argument( '--args', dest='entry_args', metavar='ARGS', default=False,
                                help='Arguments to be used for EntryPoint (ex: "arg1 arg2 arg3")')
  
        win_pwsh_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_pwsh"),
                                help='Evasion module')

        win_pwsh_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')

        # Windows VBA (Macro) subparser
        win_vba_parser = subparsers.add_parser('windows_vba', help='Microsoft Office Macros Shellcode Loader (VBA)')

        win_vba_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_vba_parser.add_argument('--x86', metavar='X86_SHELLCODE',dest='shellcode32_variable',
                                help='Specify a raw x86 shellcode file (if template support it)')

        win_vba_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_vba"),
                                help='Shellcode-loading method')
        
        win_vba_parser.add_argument('--doctype', dest='doctype', default="doc",
                            choices=["doc", "xl"],
                            help='Word or Excel Document type. Default: doc')

        win_vba_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_vba"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_vba_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="",
                                help='Process name for shellcode injection')

        win_vba_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions', metavar='EVASION[:ARGS]', 
                                   help=f'Evasion module (e.g., sleep or sleep:10). Available: {", ".join(self.get_available_files("evasions", platform="windows_vba"))}')


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
        
        win_js_parser.add_argument('-v', '--version', dest='dot2js_version', metavar='DOTNET2JS_VERSION', choices=["auto", "2", "4"], default="auto",
                                help='Specify .NET version to use for SharpShooter like templates')

        win_js_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')
        
    

        # Windows HTA subparser
        win_hta_parser = subparsers.add_parser('windows_hta', help='HTA Windows Shellcode Loader')

        win_hta_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_hta_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_hta"),
                                help='Shellcode-loading method')

        win_hta_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_hta"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_hta_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="",
                                help='Process name for shellcode injection')

        win_hta_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_hta"),
                                help='Evasion module')
        
        win_hta_parser.add_argument('-v', '--version', dest='dot2js_version', metavar='DOTNET2JS_VERSION', choices=["auto", "2", "4"],
                                help='Specify .NET version to use for SharpShooter like templates')

        win_hta_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')

        # Windows VBS subparser
        win_vbs_parser = subparsers.add_parser('windows_vbs', help='Windows VBScript Shellcode Loader')

        win_vbs_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_vbs_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_vbs"),
                                help='Shellcode-loading method')

        win_vbs_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_vbs"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_vbs_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="",
                                help='Process name for shellcode injection')

        win_vbs_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_vbs"),
                                help='Evasion module')

        win_vbs_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
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
 
         # Windows WIX subparser
        win_wix_parser = subparsers.add_parser('windows_wix', help='Windows Installer XML (WIX) Loader, for Windows Installer (.msi) files')

        win_wix_parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the raw shellcode file')

        win_wix_parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods", platform="windows_wix"),
                                help='Shellcode-loading method')

        win_wix_parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.get_available_files("encryptors", platform="windows_wix"),
                                help='Encryption/Encoding algorithm to be applied to the shellcode')

        win_wix_parser.add_argument('-em', '--evasion-module', action='append', dest='evasions',
                                choices=self.get_available_files("evasions", platform="windows_wix"),
                                help='Evasion module')

        win_wix_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
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
        
# Find where the evasion modules are added to the argument parser for Linux
        lin_parser.add_argument('-em', '--evasion-module', dest='evasions', metavar='EVASION[:ARGS]', 
                                action='append', 
                                help=f'Evasion module (e.g., sleep or sleep:10). Available: {", ".join(self.get_available_files("evasions", platform="linux"))}')

        #lin_parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default=False,
        #                        help='Process name for shellcode injection')

        lin_parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc",
                                help='Output filename')

        #lin_parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
        #                        help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

        # Add a utils subparser
        utils_parser = subparsers.add_parser('utils', help='Utility functions')
        utils_subparsers = utils_parser.add_subparsers(dest='util_command', help='Utility command')
        
        # Add insert-xml subcommand with updated help text
        insert_xml_parser = utils_subparsers.add_parser('insert-xml', help='Insert custom XML part into Office document (creates document if it doesn\'t exist)')
        insert_xml_parser.add_argument('--doc', '-d', required=True, help='Path to the Office document (.docx, .xlsx, .pptx) - will be created if it doesn\'t exist')
        insert_xml_parser.add_argument('--xml', '-x', required=True, help='Path to the XML file to insert')
        insert_xml_parser.add_argument('--output', '-o', help='Path to save the modified document (default: overwrite original)')
        
        # Add list-xml subcommand
        list_xml_parser = utils_subparsers.add_parser('list-xml', help='List custom XML parts in Office document')
        list_xml_parser.add_argument('--doc', '-d', required=True, help='Path to the Office document (.docx, .xlsx, .pptx)')
        
        # Add extract-xml subcommand
        extract_xml_parser = utils_subparsers.add_parser('extract-xml', help='Extract custom XML parts from Office document')
        extract_xml_parser.add_argument('--doc', '-d', required=True, help='Path to the Office document (.docx, .xlsx, .pptx)')
        extract_xml_parser.add_argument('--output', '-o', help='Directory to save the extracted XML files (default: current directory)')
        
        # Make utils_parser show help when no subcommand is provided
        utils_parser.set_defaults(func=lambda args: utils_parser.print_help())

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

    def get_compiler(self):
        # Platforms that don't need a compiler
        if self.platform in ["windows_pwsh", "windows_vba", "windows_js", "windows_hta", "windows_vbs", "windows_wix"]:
            return ""
        
        # Platform-specific compiler mapping
        compiler_map = {
            "windows_cs": "mono-csc",
            "windows_cpp": "MinGW",
            "windows_aspx": "mono-csc",
            "linux": "gcc",
            # Add new platforms here with their default compilers
        }
        
        # Handle LLVM obfuscator override
        if self.llvmo and self.platform in ["windows_cpp", "linux"]:
            return "LLVM-Obfuscator"
            
        return compiler_map.get(self.platform, "")

    def run(self):
        # Parsing arguments
        args = self.parse_arguments()
        for key, value in vars(args).items():
            setattr(self, key, value)

        # Handle utils commands
        if hasattr(args, 'platform') and args.platform == 'utils':
            if hasattr(args, 'func') and args.util_command is None:
                # No subcommand specified, show help for utils
                args.func(args)
                return
            if args.util_command == 'insert-xml':
                insert_custom_xml(args.doc, args.xml, args.output)
                return
            elif args.util_command == 'list-xml':
                from core.utils.office_utils import list_custom_xml
                list_custom_xml(args.doc)
                return
            elif args.util_command == 'extract-xml':
                from core.utils.office_utils import extract_custom_xml
                extract_custom_xml(args.doc, args.output)
                return

        # TO DO
        # Obfuscation for .NET & Powershell
        # SandBox_evasion: EKKO Sleep, NoVMenv....
        # AMSI + ETW Patching evasion modules
        # SGN Encoder ?
        # Windows Process injection Templates C++/C# 
        # Linux Process injection Templates C++/C#
        

    

        #### OUTPUTS  #####
        if self.platform != "utils":
            self.compiler = self.get_compiler()
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
                    ("Dot2Js Version", self.dot2js_version),
                    ("Entry Point", loader.class_name),
                    ("Entry Function", loader.function_name),
                    ("Entry Args", loader.entry_args),
                    ("Target Arch", loader.arch),
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
            
            print(f"\n{Fore.GREEN}============================================================{Fore.RESET}")
            print(f"{Fore.CYAN}Analysis of {loader.outfile}:{Fore.RESET}")
            print(size(loader.outfile))
            print(sha256sum(loader.outfile))
            print(entropy(loader.outfile))
            print(f"{Fore.GREEN}============================================================{Fore.RESET}")
    

        else:
            from core.utils.utils import file_to_bytearray,bytearray_to_cpp_sc
            print(f'{Fore.GREEN}Hex Shellcode:\t\t{Fore.WHITE}')
            print(bytearray_to_cpp_sc(file_to_bytearray(self.shellcode_variable,),method=0, sc_var_name=self.name))

            print(f'\n{Fore.GREEN}Array Shellcode:\t\t{Fore.WHITE}')
            print(bytearray_to_cpp_sc(file_to_bytearray(self.shellcode_variable,),method=1, sc_var_name=self.name))
            pass
