import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent


class PerunsFart(Evasion):
    def __init__(self, platform):
        super().__init__(platform)
        self.uuid = uuid.uuid4().hex

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cs":
            module.components = [
                DefineComponent("using System.Collections;\n"),
                #DefineComponent(f"using perF{str(self.uuid)};\n"),
                CodeComponent(code.replace("####UUID####",str(self.uuid))),
                EvasionComponent(f"perF{str(self.uuid)}.Structs.PerunsFart();")
            ]
        return module

    def test(self):
        print("hello PerunsFart")