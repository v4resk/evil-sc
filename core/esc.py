import argparse
import os
import random
import string
from colorama import init, Fore
from core.utils.utils import *
from core.utils.CustomArgFormatter import CustomArgFormatter
from core.config.config import Config
from core.controlers.TemplateLoader import TemplateLoader
from core.controlers.EncryptorsChain import EncryptorsChain


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
        self.method = ""
        self.encoders = []
        self.encryptors = []
        self.encryptors_keys = []
        self.sandbox_evasion = []
        self.evil_sc_template_file = ""
        self.outfile = ""

        self.valid_encryptors = ["base64","xor","nop"]


    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='Template-based shellcode loader', formatter_class=CustomArgFormatter)
        parser.add_argument('shellcode_variable', metavar='shellcode', help='Specify the shellcode variable')

        parser.add_argument('-m', '--method', dest='method', required=True, choices=self.get_available_files("methods"),
                            help='Shellcode-loading method')

        parser.add_argument('-e', '--encrypt', action='append', dest='encryptors', choices=self.valid_encryptors,
                            help='Template-dependent encryption or encoding method to be applied to the shellcode')

        parser.add_argument('-ek', '--encrypt-key', action='append', dest='encryptors_keys', metavar='KEY',
                            help=f'A key to be used for --encrypt (auto-generated if empty)')

        parser.add_argument('-p', '--process', dest='target_process', metavar='PROCESS_NAME', default="explorer.exe",
                            help='Process name for shellcode injection')

        parser.add_argument('-se', '--sandbox-evasion', action='append', dest='sandbox_evasion',
                            choices=self.get_available_files("sandboxEvasion"),
                            help=f'Sandbox evasion technique')

        parser.add_argument('-o', '--outfile', dest='outfile', metavar='OUTPUT_FILE', default="evil-sc.exe",
                            help=f'Output filename')

        parser.add_argument('--encoder', action='append', dest='encoders', metavar='ENCODER',
                            help='Template-independent encoding method to be applied to the shellcode (default: sgn)')

        args = parser.parse_args()

        return args

    # This method return available .cpp files in a given folder, for Menu options
    def get_available_files(self, folder):
        template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', folder)
        if not os.path.exists(template_folder):
            os.makedirs(template_folder)
        available_files = [file[:-4] for file in os.listdir(template_folder) if file.endswith('.cpp')]
        return available_files


    def run(self):
        # Parsing arguments
        args = self.parse_arguments()
        self.shellcode_variable = args.shellcode_variable
        self.target_process = args.target_process
        self.method = args.method
        self.encryptors = args.encryptors
        self.sandbox_evasion = args.sandbox_evasion
        self.encryptors_keys = args.encryptors_keys
        self.outfile = args.outfile

        # TO DO
        #Do the template engine
        #Do the encoders + encoders chain
        #Do compilers
        #-------->  Make "modules" only one class ! No heritage needed, same modules pour tt
        # Les modules contienent le code a editer (ex: callComponent etc)
        loader = TemplateLoader(vars(self))
        #loader.test()
        loader.write_code()
        loader.compile()

        print()

        # Debug Prints
        print(f'{Fore.GREEN}Shellcode:\t\t{Fore.WHITE} {self.shellcode_variable}')
        print(f'{Fore.GREEN}Method:\t\t\t{Fore.WHITE} {os.path.basename(self.method)}')
        print(f'{Fore.GREEN}Encryptors:\t\t{Fore.WHITE}{self.encryptors}')
        print(f'{Fore.GREEN}Encryptors Keys:\t{Fore.WHITE}{self.encryptors_keys}')
        print(f'{Fore.GREEN}Sandbox Evasion:\t{Fore.WHITE}{[os.path.basename(file) for file in self.sandbox_evasion]}')
        print(f'{Fore.GREEN}Target Process:\t\t{Fore.WHITE}{self.target_process}')
        print(f"\n{Fore.CYAN}Genreated template:\t{Fore.WHITE}{self.evil_sc_template_file}")
        print(f"{Fore.CYAN}Output:\t\t\t{Fore.WHITE}{self.outfile}")
