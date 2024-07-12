from core.config.config import Config
from core.engines.TemplateModuleComponent import TemplateModuleComponent


class IncludeComponent(TemplateModuleComponent):
    def __init__(self, code=None):
        placeholder = Config().get("PLACEHOLDERS", "INCLUDE")
        super().__init__(code, placeholder)
        self.__code = code

    @property
    def code(self):
        return f"#include {self.__code}\n"