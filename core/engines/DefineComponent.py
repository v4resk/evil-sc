from core.config.config import Config
from core.engines.TemplateModuleComponent import TemplateModuleComponent


class DefineComponent(TemplateModuleComponent):
    def __init__(self, code=None):
        placeholder = Config().get("PLACEHOLDERS", "DEFINE")
        super().__init__(code, placeholder)
        self.__code = code

    @property
    def code(self):
        return f"{self.__code}"