# This class should create the .cpp file

from core.config.config import Config
from core.controlers.EncryptorsChain import EncryptorsChain
from core.controlers.EvasionChain import EvasionChain
from core.controlers.ShellcodeControler import ShellcodeControler
from core.controlers.CompilerControler import CompilerControler
from core.controlers.SysCallsControler import SysCallsControler

from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.DefineComponent import DefineComponent
#from core.engines.EvasionComponent import EvasionComponent
from core.engines.IncludeComponent import IncludeComponent
from core.engines.EvasionComponent import EvasionComponent
from core.engines.SysCallsComponent import SysCallsComponent
from core.utils.utils import verify_file_type

import shutil
import os
from colorama import Fore
import string
import random
import re


class TemplateLoader:
    def __init__(self,_vars):

        for key, value in _vars.items():
            setattr(self, key, value)

        if self.platform == "windows_cs":
            self.template_file = Config().get('FILES', 'cs_template_file')
        elif self.platform == "windows_pwsh":
            self.template_file = Config().get('FILES', 'pwsh_template_file')
        elif self.platform == "windows_vba":
            self.template_file = Config().get('FILES', 'vba_template_file')        
        else: 
            self.template_file = Config().get('FILES', 'cpp_template_file')

        self.isdll = False
        self.call_components = []
        self.code_components = []
        self.include_components = []
        self.define_components = []
        self.syscall_components = []
        self.evasion_components = []
        self.mingw_options = []

        self.sysCallss = None

        self.build_options = ""

        # Verify template compatibility
        self.input_file_type = verify_file_type(self.shellcode_variable)
        #self.verify_template()


        #Copy template file to build emplacement
        self.copy_new_template_file()

        #Load encryptors chain
        self.load_encryptors_chain()

        #Load Evasion chain
        self.load_evasion_chain()

        #Check Compilers compatibility + options
        self.check_ollvm()

        # Check if template need syscall and user didn't specified it
        self.check_syscalls()

        #Process Syscalls --> moved in write_code() for output beatify
        #self.load_syscalls()

        #Get Build options
        self.get_build_options()

        #Initi Shellcode Controler
        self.shellcodeControler = ShellcodeControler(self.shellcode_variable, self.encryptors_chain, self.platform)

        if self.shellcode32_variable:
            self.shellcode32bControler = ShellcodeControler(self.shellcode32_variable, self.encryptors_chain, self.platform)

    def copy_new_template_file(self):
        src_file = f"{Config().get('FOLDERS', 'methods')}/{self.platform}/{self.method}.esc"
        dest_file = self.template_file
        try:
            if not os.path.isfile(src_file):
                raise FileNotFoundError(f"The source file {src_file} does not exist.")

            dest_folder = os.path.dirname(dest_file)
            if not os.path.isdir(dest_folder):
                os.makedirs(dest_folder)
            
            # Copy the source file to the destination
            shutil.copy2(src_file, dest_file)
            #print(f"File {src_file} copied to {dest_file}.")
        
        except Exception as e:
            print(f"Error: {e}")
    
    def load_encryptors_chain(self):
        self.encryptors_chain = EncryptorsChain.from_list(self.encryptors, self.platform)
        if self.encryptors_chain:
            for key, encryptor in self.encryptors_chain.chain.items():
                encryptor_module = encryptor.translate()
                #encryptor.print_what_doing()
                self.mingw_options.append(encryptor_module.mingw_options)
                for component in encryptor_module.components:
                    self.process_component(component)


    def load_evasion_chain(self):
        self.evasion_chain = EvasionChain.from_list(self.evasions, self.platform)
        if self.evasion_chain:
            for key, evasion in self.evasion_chain.chain.items():
                evasion_module = evasion.translate()
                self.mingw_options.append(evasion_module.mingw_options)
                for component in evasion_module.components:
                    self.process_component(component)

    def load_syscalls(self):
        if self.platform == "windows_cpp":
            self.sysCallss = SysCallsControler(self.template_file, self.syscall_method,"False",recovery=self.syswhispers_recovery_method)
            if self.sysCallss:
                SysModule = self.sysCallss.get_syscall_module()
                self.mingw_options.append(SysModule.mingw_options)
                for component in SysModule.components:
                        self.process_component(component)


    def verify_template(self):
        print(f"File Type: {self.input_file_type}")
        return 0

    def process_component(self,component):
        if isinstance(component, CallComponent):
            self.call_components.append(component)
        elif isinstance(component, CodeComponent):
            self.code_components.append(component)
        elif isinstance(component, IncludeComponent):
            self.include_components.append(component)
        elif isinstance(component, DefineComponent):
            self.define_components.append(component)
        elif isinstance(component, EvasionComponent):
            self.evasion_components.append(component)
        elif isinstance(component, SysCallsComponent):
            self.syscall_components.append(component)

    def write_code(self):
        self.load_syscalls()
        with open(self.template_file, "r") as template_file:
            template_content = template_file.read()
        
        # Replace Codes
        code_placeholder = Config().get('PLACEHOLDERS', 'CODE')
        code_components_code = ""
        for component in self.code_components:
            code_components_code += component.code
        template_content = template_content.replace(code_placeholder,code_components_code)

        # Replace Calls
        call_placeholder = Config().get('PLACEHOLDERS', 'CALL')
        call_components_code = ""
        for component in self.call_components:
            call_components_code += component.code
        template_content = template_content.replace(call_placeholder,call_components_code)
        
        # Replace Includes
        include_placeholder = Config().get('PLACEHOLDERS', 'INCLUDE')
        include_components_code = ""
        for component in self.include_components:
            if component :
                include_components_code += component.code
        template_content = template_content.replace(include_placeholder,include_components_code)

        # Replace Defines
        define_placeholder = Config().get('PLACEHOLDERS', 'DEFINE')
        define_components_code = ""
        for component in self.define_components:
            if component :
                define_components_code += component.code
        template_content = template_content.replace(define_placeholder,define_components_code)

        # Replace Shellcode
        shellcode_placeholder = Config().get('PLACEHOLDERS', 'shellcode')
        template_content = template_content.replace(shellcode_placeholder,self.shellcodeControler.get_shellcode())
        
        # Replace 32bit Shellcode
        shellcode32_placeholder = Config().get('PLACEHOLDERS', 'shellcode32')
        if self.shellcode32_variable:
            template_content = template_content.replace(shellcode32_placeholder,self.shellcode32bControler.get_shellcode())
        else:
            template_content = template_content.replace(shellcode32_placeholder,self.shellcodeControler.get_shellcode())

        # Replace Shellcode_Len
        shellcode_placeholder = Config().get('PLACEHOLDERS', 'shellcode_len')
        template_content = template_content.replace(shellcode_placeholder,str(self.shellcodeControler.get_encrypted_shellcode_len()))

        # Replace Evasion
        evasion_placeholder = Config().get('PLACEHOLDERS', 'EVASION')
        evasion_components_code = ""
        for component in self.evasion_components:
            if component :
                evasion_components_code += component.code
        template_content = template_content.replace(evasion_placeholder,evasion_components_code)       

        # Replace Delay

        # Replace ARGS

        # Replace Syscalls
        syscalls_placeholder = Config().get('PLACEHOLDERS', 'SYSCALL')
        syscalls_components_code = ""
        for component in self.syscall_components:
            if component:
                syscalls_components_code += component.code
        template_content = template_content.replace(syscalls_placeholder, syscalls_components_code)

        # Randomize Syscall names
        # To adapt for SW3 and 
        #if (self.platform == "windows_cpp") and self.syscall_method == "GetSyscallStub":
        #    all_syscalls_function = set(re.findall(r'\b(NewNt\w+|Nt\w+)\b', template_content))
        #    if all_syscalls_function:
        #        print(f"{Fore.GREEN}[+] {Fore.WHITE}Randomizing Sycall names")
        #        for syscall in all_syscalls_function:
        #            new_syscall = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(7, 15)))
        #            template_content = template_content.replace(syscall,new_syscall )
        #            print(f"{syscall}--->{new_syscall}")


        # Write to file
        #print(template_content)
        with open(self.template_file, "w") as evil_sc_file:
            evil_sc_file.write(template_content)
    
    def check_ollvm(self):
        if self.llvmo is True:
            if self.syscall_method == "SysWhispers3":
                print(f"{Fore.GREEN}[+] {Fore.WHITE}SysWhispers is not compatible with Obfuscator-LLVM. Switching to GetSyscallStub\n")
                self.syscall_method = "GetSyscallStub"
    
    def check_syscalls(self):
        if self.syscall_method == "":
            with open(self.template_file, "r") as template_file:
                template_content = template_file.read()
                if Config().get('PLACEHOLDERS', 'SYSCALL') in template_content:
                   print(f"{Fore.GREEN}[+] {Fore.WHITE}Selected template need a Direct Syscall method.... Switching to GetSyscallStub\n")
                   self.syscall_method = "GetSyscallStub"

    ## Adjut build options here if needed
    def get_build_options(self):
        
        if self.compiler == "MinGW":
            if self.platform == "linux":
                if self.method == "SimpleExec":
                    self.mingw_options += " -z execstack -fno-stack-protector "
                elif self.method == "LD_PRELOAD.so":
                    self.mingw_options += " -z execstack -fPIC -shared -ldl -fpermissive "
                elif self.method == "LD_LIBRARY_PATH.so":
                    self.mingw_options += " -z execstack -Wall -fPIC -shared -ldl -fpermissive "

        elif self.compiler == "mono-csc":
            if "InstallUtil.dll" in self.method:
                self.mingw_options += " -r:System.Configuration.Install "
            
            if "InstallUtilPwsh.dll" in self.method:
                header_folder = Config().get('FOLDERS', 'HEADERS')
                self.mingw_options += f" -r:System.Configuration.Install -r:{header_folder}/System.Management.Automation.dll"

            if ".dll" in self.method:
                self.mingw_options += " /target:library "
                self.isdll = True
        
        return ""

    def compile(self):
        # Add build options from encryptchains
        mingw_options = ""
        for component in self.mingw_options:
            if component:
                mingw_options += f"{component}"

        # Compile using CompilerControler
        compiler_controler = CompilerControler(self.template_file, self.outfile, mingw_options, self.llvmo, self.platform)
        compiler_controler.compile()
        pass

    
    def test(self):
        for component in self.call_components:
            print(f"CODE:\n{component.code}")
        
        for component in self.code_components:
            print(f"CALL:\n{component.code}")

            


        