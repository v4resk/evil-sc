import random
import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent


class sleep(Evasion):
    def __init__(self, platform):
        super().__init__(platform)
        self.sleep_time = random.randrange(2, 30, 1)
        self.uuid = uuid.uuid4().hex

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [EvasionComponent(code.replace("####2####",str(2)))]
        
        elif self.platform == "windows_cs":
            module.components = [
                EvasionComponent(f"GetTimeInfo{self.uuid}.DoTimeSleep();"),
                CodeComponent(code.replace("####UUID####", self.uuid)),
                DefineComponent("using System.Threading;\n")
            ]

        elif self.platform == "windows_vba":
            module.components = [
                CodeComponent(code),
                EvasionComponent("sleep (4)"),
                
            ]        
        elif self.platform == "linux":
            module.components = [EvasionComponent(code)]

        elif self.platform == "windows_pwsh":
            module.components = [EvasionComponent(code.replace("####TIME####", str(self.sleep_time)).replace("####TIME2####", str(self.sleep_time - 0.5)))]

        return module

    def test(self):
        print("hello from SLEEP SandboxEvasion object")