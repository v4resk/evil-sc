import os
from colorama import Fore
from core.config.config import Config
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.InjectionComponent import InjectionComponent


class InjectionController:
    def __init__(self, platform, target_process=None, template_file=None):
        self.platform = platform
        self.target_process = target_process
        self.template_file = template_file
        
        # Check template capabilities
        self.has_injection_placeholder, self.has_process_placeholder = self.validate_template_compatibility(template_file)
        
        # Set default target process if needed
        self.set_default_target_process()
        
        # Get the appropriate injection module
        self.injection_module = self._get_injection_handler()
        
    def _get_injection_handler(self):
        """Get the appropriate injection handler for the platform"""
        if not self.supports_injection():
            return None
            
        if self.platform == "windows_cpp":
            return self.get_windows_cpp_injection_module()
        # Add more platforms as they become supported
        
        return None
    
    def supports_injection(self):
        """Check if the template supports injection"""
        return (self.has_injection_placeholder or self.has_process_placeholder)
    
    def set_default_target_process(self):
        """Set default target process if needed"""
        if self.supports_injection() and not self.target_process:
            self.target_process = "self"
            print(f"{Fore.GREEN}[+] {Fore.WHITE}Using default target process: {self.target_process}")
    
    def get_windows_cpp_injection_module(self):
        """Create and return a module for Windows C++ injection"""
        injection_module = Module()
        
        # Determine which code to use based on target process
        if self.target_process and self.target_process.lower() != "self":
            # Remote process injection
            injection_code = self.generate_remote_process_code()
            
            # Add includes needed for process enumeration            
            injection_module.components = [
            IncludeComponent("#include <tlhelp32.h>\n#include <tchar.h>\n"),
            ]
            
        else:
            # Local process injection
            injection_code = self.generate_local_process_code()
        
        # Add the injection component
        injection_component = InjectionComponent(injection_code)
        injection_module.add_component(injection_component)
        
        return injection_module
            
    def get_default_process(self):
        """Get the default process for this platform"""
        if self.platform.startswith("windows_"):
            return "explorer.exe"
        # Add more platforms as needed
        return None
        
    def generate_local_process_code(self):
        """Generate code for injecting into the local process"""
        return """
    // Using current process
    hProc = GetCurrentProcess();
"""
        
    def generate_remote_process_code(self):
        """Generate code for injecting into a remote process"""
        process_name = self.target_process
        return f"""
    // Find target process: {process_name}
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    process.dwSize = sizeof(process);
    
    if (Process32First(snapshot, &process)) {{
        do {{
            if (_tcsicmp(process.szExeFile, _T("{process_name}")) == 0) {{
                pid = process.th32ProcessID;
                break;
            }}
        }} while (Process32Next(snapshot, &process));
    }}
    CloseHandle(snapshot);
    
    if (pid == 0) {{
        std::cerr << "Target process not found: {process_name}" << std::endl;
        return 1;
    }}
    
    // Open handle to target process
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc == NULL) {{
        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
        return 1;
    }}
    std::cout << "Successfully opened target process: {process_name}" << std::endl;
"""
            
    def validate_template_compatibility(self, template_file):
        """Validate if the template supports injection"""
        if not template_file or not os.path.exists(template_file):
            return False, False
            
        with open(template_file, "r") as f:
            template_content = f.read()
            
        injection_placeholder = Config().get('PLACEHOLDERS', 'INJECTION')
        process_placeholder = Config().get('PLACEHOLDERS', 'PROCESS_X64')
        
        has_injection = injection_placeholder in template_content
        has_process = process_placeholder in template_content
        
        return has_injection, has_process
        
    def apply_to_template(self, template_content):
        """Apply injection code to the template content"""
        if not self.supports_injection() or not self.injection_module:
            return template_content
            
        # Replace process placeholder if present
        if self.has_process_placeholder:
            process_placeholder = Config().get('PLACEHOLDERS', 'PROCESS_X64')
            template_content = template_content.replace(process_placeholder, self.target_process)
            
        # Replace injection placeholder if present
        if self.has_injection_placeholder:
            injection_placeholder = Config().get('PLACEHOLDERS', 'INJECTION')
            # Get the injection component from the module
            for component in self.injection_module.components:
                if isinstance(component, InjectionComponent):
                    template_content = template_content.replace(injection_placeholder, component.code)
                    break
                
        return template_content