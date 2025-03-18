# This class should create the .cpp file

from core.config.config import Config
from core.controlers.EncryptorsChain import EncryptorsChain
from core.controlers.EvasionChain import EvasionChain
from core.controlers.ShellcodeControler import ShellcodeControler
from core.controlers.CompilerControler import CompilerControler
from core.controlers.SysCallsControler import SysCallsControler
from core.utils.enums.inputType import inputType
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.DefineComponent import DefineComponent
#from core.engines.EvasionComponent import EvasionComponent
from core.engines.IncludeComponent import IncludeComponent
from core.engines.EvasionComponent import EvasionComponent
from core.engines.SysCallsComponent import SysCallsComponent
from core.engines.InjectionComponent import InjectionComponent
from core.utils.utils import verify_file_type
from core.controlers.InjectionControler import InjectionController


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

        self.call_components = []
        self.code_components = []
        self.include_components = []
        self.define_components = []
        self.syscall_components = []
        self.evasion_components = []
        self.injection_components = []
        self.mingw_options = []

        self.sysCallss = None
        
        self.injection_controller = None
        self.injection = False

        self.build_options = ""

        # Verify template x64 compatibility 
        self.expected_formats, self.output_format, self.custom_output, self.compiler_args = Config().get_template_formats(self.platform, self.method)
        self.input_file_type = verify_file_type(self.shellcode_variable)
        self.is_input_compatible = self.verify_template()

        # Verify template x86 compatibility
        if self.shellcode32_variable:
            self.x86_expected_formats, self.x86_output_format, self.x86_custom_output, self.x86_compiler_args = Config().get_template_formats(self.platform, self.method)
            self.x86_input_file_type = verify_file_type(self.shellcode32_variable)
            self.x86_is_input_compatible = self.verify_template()
        else:
            self.x86_is_input_compatible = True

        if (self.is_input_compatible is False) or (self.x86_is_input_compatible is False):
            print(f"{Fore.RED}[-] {Fore.WHITE}Incompatible options for method {Fore.RED}{self.method}{Fore.WHITE}")
            print(f"{Fore.RED}[-] {Fore.WHITE}The input format {Fore.RED}{self.input_file_type.name}{Fore.WHITE} is incompatible with the expected formats: {Fore.RED}{self.expected_formats}{Fore.WHITE}")
            exit()

        self.outfile = f"{self.outfile}{self.output_format}"
        self.mingw_options.append(self.compiler_args)

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
        
        # Check injection support
        self.check_injection()
        
        # Check reflection
        self.check_reflection()

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
                        
    def load_injector(self):
        """
        Load the injection module and process its components.
        This function should be called after check_injection().
        """
        if not hasattr(self, 'injection_controller') or not self.injection_controller:
            return
    
        # Use supports_injection() instead of is_supported()
        if self.injection_controller.supports_injection():
            injection_module = self.injection_controller.injection_module
            if injection_module:
                for component in injection_module.components:
                    self.process_component(component)


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
        elif isinstance(component, InjectionComponent):
            self.injection_components.append(component)

    def write_code(self):
        self.load_syscalls()
        self.load_injector()
        
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
        shellcode = self.shellcodeControler.get_shellcode()
        template_content = template_content.replace(shellcode_placeholder,shellcode)
        
        # Replace 32bit Shellcode
        shellcode32_placeholder = Config().get('PLACEHOLDERS', 'shellcode32')
        if self.shellcode32_variable:
            template_content = template_content.replace(shellcode32_placeholder,self.shellcode32bControler.get_shellcode())
        else:
            template_content = template_content.replace(shellcode32_placeholder,shellcode)

        # Replace Shellcode_Len
        shellcode_placeholder = Config().get('PLACEHOLDERS', 'shellcode_len')
        template_content = template_content.replace(shellcode_placeholder,str(self.shellcodeControler.get_encrypted_shellcode_len()))

        # Replace Shellcode_type
        shellcodetype_placeholder = Config().get('PLACEHOLDERS', 'shellcode_type')

        shellcode_type = self.shellcodeControler.get_shellcode_type()
        template_content = template_content.replace(shellcodetype_placeholder,str(shellcode_type))

        
        # Replace Evasion
        evasion_placeholder = Config().get('PLACEHOLDERS', 'EVASION')
        evasion_components_code = ""
        for component in self.evasion_components:
            if component :
                evasion_components_code += component.code
        template_content = template_content.replace(evasion_placeholder,evasion_components_code)       

        # Replace Injection 
        injection_placeholder = Config().get('PLACEHOLDERS', "INJECTION")
        injection_components_code = ""
        for component in self.injection_components:
            if component:
                injection_components_code += component.code 
        template_content = template_content.replace(injection_placeholder, injection_components_code)
        
        # Replace Class Name
        class_name_placeholder = Config().get('PLACEHOLDERS', 'CLASS_NAME')
        template_content = template_content.replace(class_name_placeholder, self.class_name)

        # Replace Function Name
        function_name_placeholder = Config().get('PLACEHOLDERS', 'FUNCTION_NAME')
        template_content = template_content.replace(function_name_placeholder, self.function_name)
        
        # Replace Entry Args
        entry_args_placeholder = Config().get('PLACEHOLDERS', 'ENTRY_ARGS')
        template_content = template_content.replace(entry_args_placeholder, self.entry_args)
        
        # Replace Delay

        # Replace ARGS

        # Replace Syscalls
        syscalls_placeholder = Config().get('PLACEHOLDERS', 'SYSCALL')
        syscalls_components_code = ""
        for component in self.syscall_components:
            if component:
                syscalls_components_code += component.code
        template_content = template_content.replace(syscalls_placeholder, syscalls_components_code)
        
        # Replace NullGate Syscalls
        if self.syscall_method == "NullGate":
            template_content = self.sysCallss.process_template_NullGate_syscalls(template_content)

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
                   print(f"{Fore.GREEN}[+] {Fore.WHITE}Selected template need a Indirect/Direct Syscall method.... ")
                   print(f"{Fore.GREEN}[+] {Fore.WHITE}Switching to Indirest Syscall with NullGate\n")
                   self.syscall_method = "NullGate"
                   
    def check_injection(self):
        """
        Check if injection is supported by the template and set default values.
        This function should be called after the template file is set.
        """
        # Skip if platform doesn't support injection yet
        if self.platform != "windows_cpp":
            self.target_process = None
            return

        # Initialize injection controller to check template compatibility
        self.injection_controller = InjectionController(
            self.platform, 
            self.target_process,
            self.template_file
        )
        
        # Update target_process with the possibly modified value from the controller
        self.target_process = self.injection_controller.target_process
        
        # Set injection flag based on template support
        self.injection = self.injection_controller.supports_injection()
        
        
    def check_reflection(self):
        """
        Checks if the template uses reflection placeholders and validates required parameters.
        Sets default values for function_name and entry_args if needed.
        """
        # Read the template file content
        with open(self.template_file, 'r') as f:
            template_content = f.read()

        # Get placeholders from config
        class_name_placeholder = Config().get('PLACEHOLDERS', 'class_name')
        function_name_placeholder = Config().get('PLACEHOLDERS', 'function_name')
        entry_args_placeholder = Config().get('PLACEHOLDERS', 'entry_args')

        # Check if template uses any of the reflection placeholders
        uses_reflection = (class_name_placeholder in template_content or 
                          function_name_placeholder in template_content or 
                          entry_args_placeholder in template_content)

        if not uses_reflection:
            # Template doesn't use reflection, set values to None
            self.class_name = None
            self.function_name = None
            self.entry_args = None
            return

        # Template uses reflection, validate required parameters
        if not hasattr(self, 'class_name') or not self.class_name:
            from colorama import Fore
            print(f"{Fore.RED}[!] Error: {Fore.WHITE}This template requires a class name to be specified with -c/--classname")
            print(f"{Fore.RED}[!] {Fore.WHITE}Example: -c 'namespace.classname'")
            exit(1)

        # Set default values if not provided
        if not hasattr(self, 'function_name') or not self.function_name:
            self.function_name = "Main"
            from colorama import Fore
            print(f"{Fore.YELLOW}[*] {Fore.WHITE}No function specified, using default: {self.function_name}")

        if not hasattr(self, 'entry_args') or not self.entry_args:
            self.entry_args = ""

    ## Adjut build options here if needed
    def get_build_options(self):

        # DLL Compile options
        if self.platform == "linux" and self.output_format == ".so":
            self.mingw_options += " -fPIC -shared -ldl -fpermissive "
        if self.platform == "windows_cs" and self.output_format == ".dll":
            self.mingw_options += " /target:library "

        return ""

    def verify_template(self):
        """
        Verify if the input format matches any of the expected formats or if expected_formats include 'ALL'.

        Args:
            input_format (inputType): The actual input format as an inputType enum.
            expected_formats (str): A comma-separated string of expected formats or 'ALL'.

        Returns:
            bool: True if the input format matches one of the expected formats, False otherwise.
        """
        
        # Handle 'ALL' case
        if "ANY" in self.expected_formats.upper():
            return True

        # Split expected formats into a list and map them to enums
        expected_enums = [
            inputType.from_string(fmt.strip()) for fmt in self.expected_formats.split(",")
        ]

        # Remove any None values from the list (for invalid formats)
        expected_enums = [fmt for fmt in expected_enums if fmt is not None]

        # Check if the input format matches any of the expected enums
        return self.input_file_type in expected_enums

    def compile(self):
        # Add build options from encryptchains
        mingw_options = ""
        for component in self.mingw_options:
            if component:
                mingw_options += f"{component}"

        # Compile using CompilerControler
        compiler_controler = CompilerControler(self.template_file, self.outfile, mingw_options, self.llvmo, self.platform, self.custom_output)
        compiler_controler.compile()
        pass

    
    def test(self):
        for component in self.call_components:
            print(f"CODE:\n{component.code}")
        
        for component in self.code_components:
            print(f"CALL:\n{component.code}")

            


        