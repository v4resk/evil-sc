import sys
from abc import ABC, abstractmethod
import os
from colorama import init, Fore

from core.config.config import Config


class Encryptor(ABC):

    def __init__(self, platform ,order=None):
        self.implementations_dir = Config().get("FOLDERS", "encryptors")
        self.decoder_in = None
        self.decoder_out = None
        self.order = order
        self.isStringShellcode = False
        self.platform = platform
        pass

    def set_order(self, order):
        self.order = order

    @abstractmethod
    def encode(self, data):
        pass

    @abstractmethod
    def decode(self, data):
        pass

    @abstractmethod
    def translate(self):
        pass

    def to_string(self):
        return self.__class__.__name__.lower()
    
    def print_what_doing(self):
        print(f"{Fore.CYAN}[+] {Fore.WHITE}{self.__class__.__name__.upper()} Encrytion Done")

    # To edit, function that will retreive the .cpp implementation
    def template(self):
        encoder = self.__class__.__name__.lower()
        source = f"{self.implementations_dir}/{self.platform}/{encoder}.esc"

        if not os.path.exists(source):
            print(f"[-] {encoder} not supported -> source: {source}")
            sys.exit(1)
        return open(str(source)).read()
