import os

class CompilerControler:
    def __init__(self,evil_sc_template_file,outfile,compile_options=""):
        self.evil_sc_template_file = evil_sc_template_file
        self.outfile = outfile
        self.compile_options = "-static-libgcc -static-libstdc++" + f" {compile_options}"

    def compile(self):
        os.system(f"x86_64-w64-mingw32-g++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options}")