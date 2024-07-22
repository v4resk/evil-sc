from core.config.config import Config
from core.engines.SysCallsComponent import SysCallsComponent
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.controlers.Module import Module


class SysCallsControler:
    def __init__(self,evil_sc_template_file,sysCallsType,hashSyscalls):
        self.evil_sc_template_file = evil_sc_template_file
        self.sysCallsType = sysCallsType
        self.hashSyscalls = hashSyscalls

        self.sysModule = self.compute_syscall_module()

        #debug
        print(vars(self))

    def compute_syscall_module(self):
        module = None
        if self.sysCallsType == "":
            module = self.get_noSysCall_module()

        elif self.sysCallsType == "GetSyscallStub":
            module = self.get_GetSyscallStub_module()

        elif self.sysCallsType == "SysWhispers2":
            module = self.get_SysWhispers2_module()

        elif self.sysCallsType == "SysWhispers3":
            module = self.get_SysWhispers3_module()
    
        return module

    def get_noSysCall_module(self):
        module = Module()
        return module

    def get_GetSyscallStub_module(self):
        module = Module()
        return module

    def get_SysWhispers2_module(self):
        module = Module()
        return module

    def get_SysWhispers3_module(self):
        module = Module()
        return module

    def hashSyscalls(self):
        pass

    def get_template_functions(self):
        pass

    def get_syscall_module(self):
        return self.sysModule

    