import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent
from colorama import Fore

class user(Evasion):
    def __init__(self, platform, args=None):
        super().__init__(platform, args)
        if not args or len(args) == 0:
            raise ValueError("User evasion module requires a username argument (-em user:username)")
        self.username = args[0]
        self.uuid = uuid.uuid4().hex

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cs":
            module.components = [
               
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####USERNAME####", self.username)),
                EvasionComponent(f"UserCheck{self.uuid}.CheckCurrentUser();")
            ]
        elif self.platform == "windows_cpp":
            module.components = [
                DefineComponent("#include <windows.h>\n"),
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####USERNAME####", self.username)),
                EvasionComponent(f"CheckUser{self.uuid}();")
            ]
        elif self.platform == "windows_vba":
            module.components = [
                EvasionComponent(f"CheckUser{self.uuid}"),
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####USERNAME####", self.username))
            ]

        return module 