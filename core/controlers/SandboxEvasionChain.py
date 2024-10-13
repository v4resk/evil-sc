# This class should create the encoders chain
from collections import OrderedDict
from pydoc import locate
from core.sandboxEvasion.SandboxEvasion import SandboxEvasion
from core.config.config import Config

debug_mode = Config().get("DEBUG", "SANDBOXEVASION")

class SandboxEvasionChain:
    def __init__(self):
        self.chain = OrderedDict()
        self.current = 0

    def is_empty(self):
        return len(self.chain) == 0

    def to_string(self):
        return "->".join([e.__class__.__name__ for e in self.chain.values()])
    
    def push(self, value: SandboxEvasion):
        value.order = self.current
        self.chain[self.current] = value
        self.current += 1

    def pop(self) -> SandboxEvasion:
        self.current -= 1
        return self.chain.popitem()[1]

    def delete(self, index) -> bool:
        if index not in self.chain.keys():
            return False
        self.chain.move_to_end(index)
        self.chain.popitem()
    
    
    @staticmethod
    def from_list(sandboxevasion: list = None, platform="windows_cpp"):
        chain = SandboxEvasionChain()
        if not sandboxevasion or len(sandboxevasion) == 0:
            return chain
        for e in sandboxevasion:
            try:
                    sandboxevasion_class_string = f"core.sandboxEvasion.{e}.{e}"
                    sandboxevasion_class = locate(sandboxevasion_class_string)
                    sandboxevasion_instance = sandboxevasion_class(platform)

                    if debug_mode == "True":
                        print(sandboxevasion_instance.translate().sandboxevasion_components.code)
                        pass     

                    chain.push(sandboxevasion_instance)
            except Exception as ex:
                print(ex)
                continue
        return chain
