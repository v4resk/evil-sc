import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent


class RareAPI(Evasion):
    def __init__(self, platform, args=None):
        super().__init__(platform, args)
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
        elif self.platform == "windows_cpp":
            module.components = [
                DefineComponent("#include <windows.h>\n"),
                CodeComponent(code.replace("####UUID####", self.uuid)),
                EvasionComponent(f"CheckRareAPI{self.uuid}();")
            ]
        elif self.platform == "windows_aspx":
            module.components = [
                EvasionComponent(code),
                DefineComponent("[System.Runtime.InteropServices.DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]\nprivate static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);\n"),
                DefineComponent("[System.Runtime.InteropServices.DllImport(\"kernel32.dll\")]\nprivate static extern IntPtr GetCurrentProcess();\n"),
            ]

        return module

    def test(self):
        print("hello from SLEEP SandboxEvasion object")