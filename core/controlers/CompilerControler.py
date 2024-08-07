import os
from core.config.config import Config

debug_mode = Config().get("DEBUG", "COMPILER")

class CompilerControler:
    def __init__(self,evil_sc_template_file,outfile,compile_options="", llvmo=False):
        self.evil_sc_template_file = evil_sc_template_file
        self.outfile = outfile
        self.llvmo = llvmo
        self.compile_options = f" -static-libgcc -static-libstdc++ {compile_options}"
        self.llvmo_options = " -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1"

    def compile(self):
        
        # If not using LLVM Obf
        if self.llvmo is False:
            if debug_mode == "True":
                print(f"x86_64-w64-mingw32-g++ {self.evil_sc_template_file} -o {self.outfile}{self.compile_options}")
            os.system(f"x86_64-w64-mingw32-g++ {self.evil_sc_template_file} -o {self.outfile}{self.compile_options}")
        else:
            if debug_mode == "True":
                print(f"x86_64-w64-mingw32-clang++ {self.evil_sc_template_file} -o {self.outfile}{self.compile_options}{self.llvmo_options}")
            os.system(f"x86_64-w64-mingw32-clang++ {self.evil_sc_template_file} -o {self.outfile}{self.compile_options}{self.llvmo_options}")