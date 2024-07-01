import sys
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
import os

from core.config.config import Config


class Encryptor(ABC):

    def __init__(self, order=None):
        self.implementations_dir = Config().get("FOLDERS", "encryptors")
        self.decoder_in = None
        self.decoder_out = None
        self.order = order
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

    # To edit, function that will retreive the .cpp implementation
    def template(self):
        encoder = self.__class__.__name__.lower()
        source = f"{self.implementations_dir}/{encoder}.cpp"

        if not os.path.exists(source):
            print(f"[-] {encoder} not supported -> source: {source}")
            sys.exit(1)
        return open(str(source)).read()
