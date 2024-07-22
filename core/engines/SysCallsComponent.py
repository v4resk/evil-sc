from core.config.config import Config
from core.engines.TemplateModuleComponent import TemplateModuleComponent
from enum import Enum

class SyscallMethod(Enum):
    SysWhispers2 = 1
    SysWhispers3 = 2
    GetSyscallStub = 3

class SysCallsComponent(TemplateModuleComponent):
    def __init__(self, code=None):
        placeholder = Config().get("PLACEHOLDERS", "SYSCALL")
        super().__init__(code, placeholder)
        self.__code = code

    @property
    def code(self):
        return f"{self.__code}\n"