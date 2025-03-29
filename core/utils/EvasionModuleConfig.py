# New file: core/utils/EvasionModuleConfig.py
class EvasionModuleConfig:
    def __init__(self, module_string):
        # Parse module_string format: "module:arg1,arg2,..."
        parts = module_string.split(':')
        self.module_name = parts[0]
        self.args = parts[1].split(',') if len(parts) > 1 else []

    @property
    def has_args(self):
        return len(self.args) > 0

    def get_first_arg(self):
        return self.args[0] if self.has_args else None