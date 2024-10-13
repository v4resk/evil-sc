import os
from core.config.config import Config
from colorama import init, Fore

debug_mode = Config().get("DEBUG", "COMPILER")

class CompilerControler:
    def __init__(self,evil_sc_template_file,outfile,compile_options, llvmo , platform):
        self.evil_sc_template_file = evil_sc_template_file
        self.outfile = outfile
        self.llvmo = llvmo
        self.platform = platform
        self.compile_options = compile_options
        self.llvmo_options = " -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=3 -mllvm -sub_loop=2"

    def compile(self):
        
        if(self.platform == "windows_cpp"):
            # If not using LLVM Obf
            self.compile_options += " -static-libgcc -static-libstdc++ "
            if self.llvmo is False:
                if debug_mode == "True":
                    print(f"{Fore.GREEN}Compiling: {Fore.WHITE} x86_64-w64-mingw32-g++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options}\n")
                os.system(f"x86_64-w64-mingw32-g++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options}")
            else:
                if debug_mode == "True":
                    print(f"{Fore.GREEN}Compiling: {Fore.WHITE} x86_64-w64-mingw32-clang++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options} {self.llvmo_options}\n")
                os.system(f"x86_64-w64-mingw32-clang++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options} {self.llvmo_options}")

        elif(self.platform == "windows_cs"):
            if debug_mode == "True":
                print(f"{Fore.GREEN}Compiling: {Fore.WHITE} mono-csc -platform:x64 -unsafe {self.evil_sc_template_file} -out:{self.outfile}\n")
            os.system(f"mono-csc -platform:x64 -unsafe {self.evil_sc_template_file} -out:{self.outfile}")

        elif(self.platform == "linux"):
            #g++ -o shellcode_loader shellcode_loader.cpp
            if self.llvmo is False:
                if debug_mode == "True":
                    print(f"{Fore.GREEN}Compiling: {Fore.WHITE} clang++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options}\n")
                os.system(f"clang++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options}")
            else:
                if debug_mode == "True":
                    print(f"{Fore.GREEN}Compiling: {Fore.WHITE} clang++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options} {self.llvmo_options}")
                os.system(f"clang++ {self.evil_sc_template_file} -o {self.outfile} {self.compile_options} {self.llvmo_options}")
