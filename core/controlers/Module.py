class ModuleNotCompatibleException(Exception):
    pass


class ModuleNotLoadableException(Exception):
    pass


class ModuleNotFoundException(Exception):
    pass


class Module:
    def __init__(self, name: str = None, libraries: list = None, components: list = None):
        self.components = components if components else []
        self.libraries = libraries if libraries else []
        self.name = name
        self.order = None
        self.compile = False
        self.filter_string = ""
        self.loadable = True

        self.call_component = None
        self.code_components = None
        self.include_components = None
        self.define_components = None
        self.mingw_options = None
        self.sandboxevasion_components = None
        self.syscall_components = None

    def add_component(self, component):
        self.components.append(component)

    def generate(self, **kwargs):
        pass

    def build(self, **kwargs):
        pass

    def test(self):
        print("Hello from Module")
        print(vars(self))