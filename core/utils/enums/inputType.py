from enum import Enum


class inputType(Enum):
    RAW_BIN = 0
    NATIVE_BIN = 1
    NATIVE_DLL = 2
    DOTNET_BIN = 3
    DOTNET_DLL = 4

    @classmethod
    def from_string(cls, format_str):
        """Convert a format string to an inputType enum."""
        mapping = {
            "RAW_BIN": cls.RAW_BIN,
            "NATIVE_BIN": cls.NATIVE_BIN,
            "NATIVE_DLL": cls.NATIVE_DLL,
            "DOTNET_BIN": cls.DOTNET_BIN,
            "DOTNET_DLL": cls.DOTNET_DLL,
        }
        return mapping.get(format_str.upper(), None)