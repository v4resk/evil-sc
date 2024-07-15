import sys
from abc import ABC, abstractmethod
import os

from core.config.config import Config


class SandboxEvasion(ABC):

    def __init__(self, order=None):
        self.implementations_dir = Config().get("FOLDERS", "SANDBOXEVASION")
        self.decoder_in = None
        self.decoder_out = None
        self.order = order
        self.isStringShellcode = False
        pass

    def set_order(self, order):
        self.order = order

    @abstractmethod
    def translate(self):
        pass

    def to_string(self):
        return self.__class__.__name__.lower()

    # To edit, function that will retreive the .cpp implementation
    def template(self):
        sbevasion = self.__class__.__name__.lower()
        source = f"{self.implementations_dir}/{sbevasion}.cpp"

        if not os.path.exists(source):
            print(f"[-] {sbevasion} not supported -> source: {source}")
            sys.exit(1)
        return open(str(source)).read()
