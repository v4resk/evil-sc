#pragma once

#include <cstdint>
#include <map>
#include <minwindef.h>
#include <ntdef.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <cstdio>
#include <ctime>
#include <libloaderapi.h>
#include <stdexcept>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>


inline const std::string KEY = "FfqO3ZQ6XJ+SICAp";

extern "C" NTSTATUS NTAPI trampoline(size_t syscallNo, uintptr_t syscallAddr,
                                     size_t ArgumentsSize, ...);

namespace nullgate {

class obfuscation {
  static std::string base64Encode(const std::string &in);

  static std::string base64Decode(const std::string &in);

  static std::string xorHash(const std::string &str);

  static uint8_t char2int(char c);

public:
  static inline consteval uint64_t fnv1Const(const char *str) {
    const uint64_t fnvOffsetBasis = 14695981039346656037U;
    const uint64_t fnvPrime = 1099511628211;
    uint64_t hash = fnvOffsetBasis;
    char c{};
    while ((c = *str++)) {
      hash *= fnvPrime;
      hash ^= c;
    }
    return hash;
  }

  // Don't use for hardcoded strings, the string won't be obfuscated
  static uint64_t fnv1Runtime(const char *str);

  static std::string xorEncode(const std::string &in);

  static std::string xorDecode(const std::string &in);

  static std::vector<unsigned char> hex2bin(const std::string &hexString);
};

uint64_t obfuscation::fnv1Runtime(const char *str) {
  const uint64_t fnvOffsetBasis = 14695981039346656037U;
  const uint64_t fnvPrime = 1099511628211;
  uint64_t hash = fnvOffsetBasis;
  char c{};
  while ((c = *str++)) {
    hash *= fnvPrime;
    hash ^= c;
  }
  return hash;
}

std::string obfuscation::xorHash(const std::string &str) {
  std::string output;
  output.reserve(str.length());
  for (int i{}; i < str.length(); i++)
    output.push_back(str.at(i) ^ KEY.at(i % KEY.length()));
  return output;
}

std::string obfuscation::base64Encode(const std::string &in) {
  std::string out;

  int val = 0, valb = -6;
  for (unsigned char c : in) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
              [(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            [((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}

std::string obfuscation::base64Decode(const std::string &in) {
  // table from '+' to 'z'
  const uint8_t lookup[] = {
      62,  255, 62,  255, 63,  52,  53, 54, 55, 56, 57, 58, 59, 60, 61, 255,
      255, 0,   255, 255, 255, 255, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
      10,  11,  12,  13,  14,  15,  16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
      255, 255, 255, 255, 63,  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
      36,  37,  38,  39,  40,  41,  42, 43, 44, 45, 46, 47, 48, 49, 50, 51};
  static_assert(sizeof(lookup) == 'z' - '+' + 1);

  std::string out;
  int val = 0, valb = -8;
  for (uint8_t c : in) {
    if (c < '+' || c > 'z')
      break;
    c -= '+';
    if (lookup[c] >= 64)
      break;
    val = (val << 6) + lookup[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::string obfuscation::xorEncode(const std::string &in) {
  return base64Encode(xorHash(in));
}

std::string obfuscation::xorDecode(const std::string &in) {
  return xorHash(base64Decode(in));
}

uint8_t obfuscation::char2int(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  throw std::invalid_argument(std::string("Character is not a hex number: ") +
                              c);
}

std::vector<unsigned char> obfuscation::hex2bin(const std::string &hexString) {
  std::vector<unsigned char> byteArray;
  byteArray.reserve(hexString.size() / 2);
  for (int i{}; i < hexString.size(); i += 2) {
    byteArray.emplace_back(16 * char2int(hexString.at(i)) +
                           char2int(hexString.at(i + 1)));
  }
  return byteArray;
}

class syscalls {
  std::map<PDWORD, std::string> stubMap;
  std::unordered_map<std::string, DWORD> syscallNoMap;
  void populateStubs();
  void populateSyscalls();
  DWORD getSyscallNumber(const std::string &func);
  DWORD getSyscallNumber(uint64_t funcNameHash);
  uintptr_t getSyscallInstrAddr();

public:
  explicit syscalls();

  template <typename... Args>
  NTSTATUS Call(const std::string &funcName, Args... args) {
    // We don't care that are right know there could be more on the stack, this
    // is supposed to represent the number of args on the stack disregarding the
    // added arguments
    constexpr size_t argStackSize =
        sizeof...(args) <= 4 ? 0 : sizeof...(args) - 4;
    return trampoline(getSyscallNumber(funcName), getSyscallInstrAddr(),
                      argStackSize, std::forward<Args>(args)...);
  }

  template <typename... Args>
  NTSTATUS Call(uint64_t funcNameHash, Args... args) {
    // We don't care that are right know there could be more on the stack, this
    // is supposed to represent the number of args on the stack disregarding the
    // added arguments
    constexpr size_t argStackSize =
        sizeof...(args) <= 4 ? 0 : sizeof...(args) - 4;
    return trampoline(getSyscallNumber(funcNameHash), getSyscallInstrAddr(),
                      argStackSize, std::forward<Args>(args)...);
  }
};

syscalls::syscalls() {
  populateStubs();
  populateSyscalls();
}

void syscalls::populateStubs() {
  PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
  // ntdll is always the first module after the executable to be loaded
  const auto ntdllLdrEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
      // NIGHTMARE NIGHTMARE NIGHTMARE
      CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink->Flink,
                        LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
  const auto ntdllBase = reinterpret_cast<PBYTE>(ntdllLdrEntry->DllBase);

  const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdllBase);
  // e_lfanew points to ntheaders(microsoft's great naming)
  const auto ntHeaders =
      reinterpret_cast<PIMAGE_NT_HEADERS>(ntdllBase + dosHeaders->e_lfanew);
  const auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      ntdllBase +
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress);

  const auto functionsTable =
      reinterpret_cast<PDWORD>(ntdllBase + exportDir->AddressOfFunctions);
  const auto namesTable =
      reinterpret_cast<PDWORD>(ntdllBase + exportDir->AddressOfNames);
  const auto ordinalsTable =
      reinterpret_cast<PWORD>(ntdllBase + exportDir->AddressOfNameOrdinals);

  for (DWORD i{}; i < exportDir->NumberOfNames; i++) {
    std::string funcName =
        reinterpret_cast<const char *>(ntdllBase + namesTable[i]);
    if (funcName.starts_with(obfuscation::xorDecode("HBE="))) {
      auto funcAddr = reinterpret_cast<PDWORD>(
          ntdllBase + functionsTable[ordinalsTable[i]]);
      stubMap.emplace(funcAddr,
                      obfuscation::xorDecode("CBI=") + funcName.substr(2));
    }
  }
}

void syscalls::populateSyscalls() {
  unsigned int syscallNo{};
  for (const auto &stub : stubMap)
    syscallNoMap.emplace(stub.second, syscallNo++);
}

DWORD syscalls::getSyscallNumber(const std::string &funcName) {
  if (!syscallNoMap.contains(funcName))
    throw std::runtime_error(
        obfuscation::xorDecode("ABMfLEczPlh4JEQnaSUuBSgCS28=") + funcName);

  return syscallNoMap.at(funcName);
}

DWORD syscalls::getSyscallNumber(uint64_t funcNameHash) {
  for (const auto &ntFuncPair : syscallNoMap) {
    if (obfuscation::fnv1Runtime(ntFuncPair.first.c_str()) == funcNameHash)
      return ntFuncPair.second;
  }

  throw std::runtime_error(
      obfuscation::xorDecode("ABMfLEczPlh4IkogIWMvHzJGFyBGNDUMeA==") +
      std::to_string(funcNameHash));
}

uintptr_t syscalls::getSyscallInstrAddr() {
  auto stubBase = reinterpret_cast<PBYTE>((*stubMap.begin()).first);
  const int maxStubSize = 32; // I have no idea if it can be larger
  const BYTE syscallOpcode[] = {0x0F, 0x05, 0xC3}; // syscall; ret
  for (int i{}; i < maxStubSize; i++) {
    if (memcmp(syscallOpcode, stubBase + i, sizeof(syscallOpcode)) == 0)
      return reinterpret_cast<uintptr_t>(stubBase + i);
  }
  throw std::runtime_error(obfuscation::xorDecode(
      "BQkEI1c0dkJ4LEI9LWMgUDUfAixSNj0WMSRYJzs2IgQvCR8="));
}

} // namespace nullgate