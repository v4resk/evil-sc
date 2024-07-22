# This class should create the encoders chain
from collections import OrderedDict
from pydoc import locate
from core.encryptors.Encryptor import Encryptor
from core.config.config import Config


debug_mode = Config().get("DEBUG", "ENCODERS")

class EncryptorsChain:
    def __init__(self):
        self.chain = OrderedDict()
        self.current = 0

    def is_empty(self):
        return len(self.chain) == 0

    def to_string(self):
        return "->".join([e.__class__.__name__ for e in reversed(self.chain.values())])
    
    def push(self, value: Encryptor):
        value.order = self.current
        self.chain[self.current] = value
        self.current += 1

    def pop(self) -> Encryptor:
        self.current -= 1
        return self.chain.popitem()[1]

    def delete(self, index) -> bool:
        if index not in self.chain.keys():
            return False
        self.chain.move_to_end(index)
        self.chain.popitem()
    
    
    @staticmethod
    def from_list(encryptors: list = None):
        chain = EncryptorsChain()
        if not encryptors or len(encryptors) == 0:
            return chain
        for e in encryptors:
            try:
                    encoder_class_string = f"core.encryptors.{e}.{e}"
                    encoder_class = locate(encoder_class_string)
                    encoder_instance = encoder_class()

                    if debug_mode == "True":            
                        encoder_instance.translate().test()

                    chain.push(encoder_instance)
            except Exception as ex:
                print(ex)
                continue
        return chain
