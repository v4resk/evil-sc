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
    def __init__(self, platform, target_process=None, template_file=None, target_arch="x64"):
        self.platform = platform
        self.target_process = target_process
        self.target_process_path = None
        self.template_file = template_file
        self.target_arch = target_arch
        
        # Check template capabilities
        self.has_injection_placeholder, self.has_process_placeholder, self.has_process_path_placeholder = self.validate_template_compatibility(template_file)
        
        # Set default target process / or update if path is needed
        self._set_target_process()
        
        # Get the appropriate injection module
        self.injection_module = self._get_injection_handler()
        
    def _get_injection_handler(self):
        """Get the appropriate injection handler for the platform"""
        if not self.supports_injection():
            return None
            
        # Map platforms to their respective handler methods
        handlers = {
            "windows_cpp": self.get_windows_cpp_injection_module,
            "windows_cs": self.get_windows_cs_injection_module,
            "windows_pwsh": self.get_windows_pwsh_injection_module,
        }
        
        # Get the handler for the platform or return None if not supported
        handler = handlers.get(self.platform)
        if handler:
            return handler()
            
        return None
    
    def supports_injection(self):
        """Check if the template supports injection"""
        return (self.has_injection_placeholder or self.has_process_placeholder or self.has_process_path_placeholder)
    
    def _set_target_process(self):
        """Set default target process if needed"""
        if self.supports_injection() and not self.target_process:
            self.target_process = "self"
            print(f"{Fore.GREEN}[+] {Fore.WHITE}Using default target process: {self.target_process}")
        
        # Map process name to full path if needed
        if self.has_process_path_placeholder and self.target_process and self.target_process.lower() != "self":
            # Map common Windows processes to their paths based on architecture
            process_paths = {
                "notepad.exe": {
                    "x86": "C:\\\\Windows\\\\SysWOW64\\\\notepad.exe",
                    "x64": "C:\\\\Windows\\\\System32\\\\notepad.exe"
                },
                "cmd.exe": {
                    "x86": "C:\\\\Windows\\\\SysWOW64\\\\cmd.exe",
                    "x64": "C:\\\\Windows\\\\System32\\\\cmd.exe"
                },
                "powershell.exe": {
                    "x86": "C:\\\\Windows\\\\SysWOW64\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
                    "x64": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
                },
                "explorer.exe": {
                    "x86": "C:\\\\Windows\\\\SysWOW64\\\\explorer.exe",
                    "x64": "C:\\\\Windows\\\\System32\\\\explorer.exe"
                },
                "svchost.exe": {
                    "x86": "C:\\\\Windows\\\\SysWOW64\\\\svchost.exe",
                    "x64": "C:\\\\Windows\\\\System32\\\\svchost.exe"
                }
            }
            
            # Determine architecture path
            arch_key = "x86" if "x86" in self.target_arch.lower() else "x64"
            
            # Get process path if it exists in our mapping
            if self.target_process.lower() in process_paths:
                self.target_process_path = process_paths[self.target_process.lower()][arch_key]
            else:
                # For unknown processes, assume System32/SysWOW64 path
                base_path = "C:\\\\Windows\\\\SysWOW64\\\\" if arch_key == "x86" else "C:\\\\Windows\\\\System32\\\\"
                self.target_process_path = base_path + self.target_process
    
    
    def get_windows_pwsh_injection_module(self):
        """Create and return a module for Windows PWSH injection"""
        injection_module = Module()
        
        # IMPLEMENTATION HERE        
        
        return injection_module

    def get_windows_cs_injection_module(self):
        """Get injection code for C# templates"""
        injection_module = Module()
        
        # Add required imports first
        injection_module.components = [
            IncludeComponent("using System.Diagnostics;\nusing System.Linq;"),
        ]

        # Replace procInfo.hProcess with hProcess in template
        if not self.target_process or self.target_process.lower() == "self":
            injection_code = "IntPtr hProcess = Process.GetCurrentProcess().Handle;"
        else:
            # Remove .exe extension if present
            process_name = self.target_process.lower().replace('.exe', '')
            injection_code = f"""
                // Get handle on remote process (by name)
                string processName = "{process_name}";
                Process[] pList = Process.GetProcessesByName(processName);
                if (pList.Length == 0)
                {{
                    Console.WriteLine("[-] No such process");
                    return;
                }}
                int processId = pList.First().Id;
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (hProcess == IntPtr.Zero)
                {{
                    Console.WriteLine("[-] Failed to open remote process");
                    return;
                }}
            """

        injection_component = InjectionComponent(injection_code)
        injection_module.add_component(injection_component)
                
        return injection_module

    def get_windows_cpp_injection_module(self):
        """Create and return a module for Windows C++ injection"""
        injection_module = Module()
        
        # Determine which code to use based on target process
        if self.target_process and self.target_process.lower() != "self":
            # Remote process injection
            injection_code = self.generate_cpp_remote_process_code()
            
            # Add includes needed for process enumeration            
            injection_module.components = [
            IncludeComponent("#include <tlhelp32.h>\n#include <tchar.h>\n"),
            ]
            
        else:
            # Local process injection
            injection_code = self.generate_cpp_local_process_code()
        
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
        
    def generate_cpp_local_process_code(self):
        """Generate code for injecting into the local process"""
        return """
    // Using current process
    hProc = GetCurrentProcess();
"""
        
    def generate_cpp_remote_process_code(self):
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
        process_placeholder = Config().get('PLACEHOLDERS', 'INJECT_PROCESS')
        process_path_placeholder = Config().get('PLACEHOLDERS', 'INJECT_PROCESS_PATH')
        
        has_injection = injection_placeholder in template_content
        has_process = process_placeholder in template_content
        has_process_path = process_path_placeholder in template_content
        
        return has_injection, has_process,has_process_path
        
