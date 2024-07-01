from core.config.config import Config
from core.engines.TemplateModuleComponent import TemplateModuleComponent


class CallComponent(TemplateModuleComponent):
    def __init__(self, code=None):
        placeholder = Config().get("PLACEHOLDERS", "CALL")
        super().__init__(code, placeholder)
        self.__code = code

    def as_function_call(self, content):
        return f"{content}\n{self.code}"
