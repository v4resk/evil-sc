from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.engines.CodeComponent import CodeComponent
from core.controlers.Module import Module


class amsi(Evasion):
    def __init__(self, platform):
        super().__init__(platform)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()
        
        if self.platform == "windows_pwsh":
            module.components = [
                CodeComponent(code),
            ]
        
        return module

