import random

from core.sandboxEvasion.SandboxEvasion import SandboxEvasion
from core.engines.SandboxEvasionComponent import SandboxEvasionComponent
from core.controlers.Module import Module


class sleep(SandboxEvasion):
    def __init__(self):
        super().__init__()
        self.sleep_time = random.randrange(0, 30, 1)

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        module.components = [SandboxEvasionComponent(code.replace("####2####",str(2)))]

        return module

    def test(self):
        print("hello from SLEEP SandboxEvasion object")