import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent


class domain(Evasion):
    def __init__(self, platform, args=None):
        super().__init__(platform, args)
        self.specific_domain = args[0] if args and len(args) > 0 else None
        self.uuid = uuid.uuid4().hex

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cs":
            module.components = [
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####DOMAIN####", self.specific_domain if self.specific_domain else "")
                                .replace("####CHECK_SPECIFIC####", "true" if self.specific_domain else "false")),
                EvasionComponent(f"DomainCheck{self.uuid}.CheckDomain();")
            ]
        elif self.platform == "windows_cpp":
            module.components = [
                DefineComponent("#include <windows.h>\n#include <lmcons.h>\n"),
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####DOMAIN####", self.specific_domain if self.specific_domain else "")
                                .replace("####CHECK_SPECIFIC####", "1" if self.specific_domain else "0")),
                EvasionComponent(f"CheckDomain{self.uuid}();")
            ]

        return module