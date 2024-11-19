import configparser
import os
import json
from pathlib import Path

from core.utils.utils import get_project_root


class Config(object):
    def __init__(self, auto_load: bool = True):
        self.config = configparser.ConfigParser(allow_no_value=True, interpolation=configparser.ExtendedInterpolation())
        self.templates_config = os.path.join(get_project_root(), "config", "templates.json")
        self.default_config = os.path.join(get_project_root(), "config", "default.ini")
        self.file = os.path.join(get_project_root(), "config", "config.ini")
        if not os.path.isfile(self.file):
            self.write_default()
        if auto_load:
            self.load_config()

    def load_config(self, filename=None):
        if filename:
            self.file = Path(filename).absolute()
        try:
            self.config.read(self.file)
        except FileNotFoundError:
            print("The file specified does not exists")
            self.write_default()
        except configparser.ParsingError:
            print("Error encountered while parsing, check configuration file syntax")
        except Exception as e:
            print("Unhandled exception, contact support")
            print(f"Exception : {e}")

    def save_config(self):
        with open(self.file, 'w') as configfile:
            self.config.write(configfile)

    def get_config(self):
        return self.config

    def get_section(self, s):
        return self.config[s]

    def get_boolean(self, section, key):
        try:
            debug = int(self.get(section, key))
            return debug == 1
        except KeyError:
            return False
        except ValueError:
            return False
        except TypeError:
            return False
        except Exception as e:
            raise e

    def get_int(self, section, key):
        try:
            return int(self.get(section, key))
        except KeyError:
            return False
        except ValueError:
            return False
        except TypeError:
            return False
        except Exception as e:
            raise e

    def get_path(self, section, key):
        try:
            _path = Path(os.path.join(get_project_root(), self.get(section, key))).absolute()
            return _path
        except KeyError:
            return None
        except ValueError:
            return None
        except TypeError:
            return None
        except Exception as e:
            raise e

    def get_list(self, section, key):
        try:
            return [x.strip().encode() for x in self.get(section, key).split(",")]
        except KeyError:
            return None
        except ValueError:
            return None
        except TypeError:
            return None
        except Exception as e:
            raise e

    def get(self, s, v):
        try:
            return self.config[s][v]
        except KeyError:
            return None

    def set(self, s, v, new_value):
        self.config[s][v] = new_value

    def test(self):
        print(self.get("PLACEHOLDERS", "SHELLCODE"))

    def write_default(self):
        content = open(self.default_config).read()
        with open(self.file, "w") as default:
            default.write(content)

    
    def get_template_formats(self, platform, template):
        """Retrieve expected_format and output_format for a given platform and template."""
        section = f"{platform}:{template}"
        if self.config.has_section(section):
            expected_format = self.config.get(section, "expected_format", fallback="ANY")
            output_format = self.config.get(section, "output_format", fallback="EXE")
        else:
            #print(f"Warning: Template '{template}' not found for platform '{platform}' in config file. Using defaults settings.")
            expected_format, output_format = "ANY", ".exe"

        return expected_format, output_format


if __name__ == "__main__":
    c = Config()
    c.test()