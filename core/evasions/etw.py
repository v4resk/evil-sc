import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent


class etw(Evasion):
    def __init__(self, platform, args=None):
        super().__init__(platform, args)
        self.uuid = uuid.uuid4().hex

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cs":
            module.components = [
                CodeComponent(code.replace("####UUID####", self.uuid)),
                EvasionComponent(f"ETWPatcher{self.uuid}.PatchETW();")
            ]
        elif self.platform == "windows_cpp":
            module.components = [
                DefineComponent("#include <windows.h>\n"),
                CodeComponent(code.replace("####UUID####", self.uuid)),
                EvasionComponent(f"PatchETW{self.uuid}();")
            ]


        return module