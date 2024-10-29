import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent


class RareAPI(Evasion):
    def __init__(self, platform):
        super().__init__(platform)
        self.uuid = uuid.uuid4().hex

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()


        if self.platform == "windows_cs":
            module.components = [
                EvasionComponent(f"CheckForAPI{self.uuid}.didExist();"),
                CodeComponent(code.replace("####UUID####", self.uuid)),
                DefineComponent("")

            ]

        return module

    def test(self):
        print("hello from SLEEP SandboxEvasion object")