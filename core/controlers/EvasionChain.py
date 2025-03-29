# This class should create the encoders chain
from collections import OrderedDict
from pydoc import locate
from core.evasions.Evasion import Evasion
from core.config.config import Config

debug_mode = Config().get("DEBUG", "EVASION")

class EvasionChain:
    def __init__(self):
        self.chain = OrderedDict()
        self.current = 0

    def is_empty(self):
        return len(self.chain) == 0

    def to_string(self):
        return "->".join([e.__class__.__name__ for e in self.chain.values()])
    
    def push(self, value: Evasion):
        value.order = self.current
        self.chain[self.current] = value
        self.current += 1

    def pop(self) -> Evasion:
        self.current -= 1
        return self.chain.popitem()[1]

    def delete(self, index) -> bool:
        if index not in self.chain.keys():
            return False
        self.chain.move_to_end(index)
        self.chain.popitem()
    
    
    @staticmethod
    def from_list(evasion: list = None, platform="windows_cpp"):
        chain = EvasionChain()
        if not evasion or len(evasion) == 0:
            return chain
        
        for e in evasion:
            try:
                # Parse module name and arguments
                parts = e.split(':')
                module_name = parts[0]
                args = parts[1].split(',') if len(parts) > 1 else []
                
                # Get the evasion class
                evasion_class_string = f"core.evasions.{module_name}.{module_name}"
                evasion_class = locate(evasion_class_string)
                
                # Create instance with platform and args
                evasion_instance = evasion_class(platform, args)

                if debug_mode == "True":
                    print(evasion_instance.translate().evasion_components.code)
                    pass     

                chain.push(evasion_instance)
            except Exception as ex:
                print("Error creating evasion module:", ex)
                continue
        return chain
