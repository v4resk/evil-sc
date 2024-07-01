from abc import ABC


class TemplateModuleComponent(ABC):
    def __init__(self, code=None, placeholder=None, trail=False):
        self.placeholder = placeholder
        self.__code = code
        self.trail = trail

    @property
    def code(self):
        if not self.trail:
            return self.__code
        else:
            return f"{self.__code};\n{self.placeholder}"

    def as_function_call(self, content):
        pass

    def use_placeholder(self):
        if self.placeholder and self.placeholder[:2] != "//":
            self.placeholder = f"//{self.placeholder}"
