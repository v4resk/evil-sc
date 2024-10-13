import random

from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module


class sleep(Evasion):
    def __init__(self, platform):
        super().__init__(platform)
        self.sleep_time = random.randrange(0, 30, 1)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [EvasionComponent(code.replace("####2####",str(2)))]
        
        elif self.platform == "windows_cs":
            module.components = [
                EvasionComponent(code),
                DefineComponent("using System.Threading;\n")
            ]
        
        elif self.platform == "linux":
            module.components = [EvasionComponent(code)]

        return module

    def test(self):
        print("hello from SLEEP SandboxEvasion object")