import random
import uuid
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.engines.CallComponent import CallComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent


class sleep(Evasion):
    def __init__(self, platform, args=None):
        super().__init__(platform, args)
        # Use provided sleep time if specified, otherwise random
        if args and len(args) > 0:
            try:
                self.sleep_time = int(args[0])
            except ValueError:
                self.sleep_time = random.randrange(2, 30, 1)
        else:
            self.sleep_time = random.randrange(2, 30, 1)
        
        # Calculate in milliseconds for when needed
        self.sleep_time_ms = self.sleep_time * 1000
        self.verify_time = self.sleep_time - 0.5
        
        self.uuid = uuid.uuid4().hex

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cpp":
            module.components = [EvasionComponent(code.replace("####2####",str(2)))]
            
        elif self.platform == "linux":
            module.components = [
                EvasionComponent(f"sleep_with_verification{self.uuid}();"),
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####SLEEP_TIME####", str(self.sleep_time))
                                .replace("####VERIFY_TIME####", str(self.verify_time))),
                DefineComponent("#include <time.h>\n"),
                DefineComponent("#include <unistd.h>\n")
                ]
            
        
        elif self.platform == "windows_cs":
            module.components = [
                EvasionComponent(f"GetTimeInfo{self.uuid}.DoTimeSleep();"),
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####SLEEP_TIME####", str(self.sleep_time_ms))
                                .replace("####VERIFY_TIME####", str(self.verify_time))),
                DefineComponent("using System.Threading;\n")
            ]

        elif self.platform == "windows_vba":
            module.components = [
                DefineComponent("Private Declare PtrSafe Function Sleep Lib \"KERNEL32\" (ByVal mili As Long) As Long\n"),
                CodeComponent(code.replace("####SLEEP_TIME####", str(self.sleep_time_ms))
                                   .replace("####VERIFY_TIME####", str(self.verify_time))
                                   .replace("####UUID####", str(self.uuid))),
                CallComponent(f"Sleep{self.uuid}")
            ]
            

        elif self.platform == "windows_pwsh":
            module.components = [EvasionComponent(code.replace("####TIME####", str(self.sleep_time)).replace("####TIME2####", str(self.sleep_time - 0.5)))]

        return module

    def test(self):
        print("hello from SLEEP SandboxEvasion object")