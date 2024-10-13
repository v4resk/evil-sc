from core.config.config import Config
from core.engines.TemplateModuleComponent import TemplateModuleComponent


class EvasionComponent(TemplateModuleComponent):
    def __init__(self, code=None):
        placeholder = Config().get("PLACEHOLDERS", "evasion")
        super().__init__(code, placeholder)
        self.__code = code

    @property
    def code(self):
        return f"{self.__code}\n"