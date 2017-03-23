

#include "Patcher.h"
#ifdef PATCHER_MINHOOK
#include "MinHook.h"
#endif
#include <unordered_map>
#include <algorithm>

namespace Patcher {

static std::vector<std::shared_ptr<patch>> allPatches;
static std::unordered_map<BYTE*, BYTE> originalBytes;
static std::unordered_map<HMODULE, uintptr_t> modulePrefAddr;
static HMODULE baseModule = nullptr;
#ifdef PATCHER_MINHOOK
static int minHookCount = 0;
#endif

static bool InitBaseModule();
static HMODULE GetModuleFromAddress(void *address);

// Memory patch class functions

// Recommended to use one of the Patch factory functions to instantiate
// Use Unpatch to handle deletion of patches created by Patch functions

MemPatch::MemPatch(void *_address, size_t patchSize, const void *newBytes,
                   const void *expectedBytes, bool enable) {
  address = _address;
  size = patchSize;

  if ((invalid = !address || !size || !newBytes)) {
    return;
  }

  newBytesBuffer.reset(new BYTE[size]);
  oldBytesBuffer.reset(new BYTE[size]);
  if ((invalid = (!newBytesBuffer || !oldBytesBuffer ||
                  memcpy(newBytesBuffer.get(), newBytes, size) !=
                  newBytesBuffer.get()))) {
    return;
  }

  DWORD oldAttr;
  // Test expected bytes vs. actual, and copy original bytes
  if ((invalid = !VirtualProtect(address, size, PAGE_EXECUTE_READWRITE,
                                 &oldAttr))) {
    return;
  }

  if (!(invalid = expectedBytes && memcmp(expectedBytes, address, size) != 0)) {
    // Copy old bytes
    for (size_t i = 0; i < size; ++i) {
      auto *p = reinterpret_cast<BYTE*>(address) + i;
      if (originalBytes.count(p) == 0) {
        originalBytes[p] = *p;
      }

      oldBytesBuffer[i] = originalBytes[p];
    }
  }

  VirtualProtect(address, size, oldAttr, &oldAttr);

  if (invalid) {
    return;
  }

  if (enable) {
    Enable();
  }
  else {
    GetModuleInfo(module, moduleHash);
  }
}

MemPatch::~MemPatch() {
  Disable();
}

bool MemPatch::Enable(bool force) {
  if (enabled && !force) {
    return true;
  }
  else if (invalid) {
    return false;
  }

  if (!VerifyModule()) {
    return !(invalid = true);
  }

  DWORD oldAttr;
  if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldAttr)) {
    return false;
  }
  memcpy(address, newBytesBuffer.get(), size);
  VirtualProtect(address, size, oldAttr, &oldAttr);

  return (enabled = true);
}

bool MemPatch::Disable(bool force) {
  if (!enabled && !force) {
    return true;
  }
  else if (invalid) {
    return false;
  }

  if (!VerifyModule()) {
    return !(invalid = true);
  }

  DWORD oldAttr;
  if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldAttr)) {
    return false;
  }
  memcpy(address, oldBytesBuffer.get(), size);
  VirtualProtect(address, size, oldAttr, &oldAttr);

  return !(enabled = false);
}

#ifdef PATCHER_MINHOOK
// MinHook patch class functions

MHPatch::MHPatch(void *function, const void *_newFunction, bool enable) {
  address = function;
  newFunction = _newFunction;
  trampoline = nullptr;

  if (minHookCount == 0) {
    MH_STATUS status = MH_Initialize();
    if (status == MH_ERROR_ALREADY_INITIALIZED) {
      // Initialized elsewhere, so block this class from uninitializing it
      ++minHookCount;
    }
    else if ((invalid = status != MH_OK)) {
      return;
    }
  }
  ++minHookCount;

  if ((invalid = !address || !newFunction ||
                 MH_CreateHook(address, newFunction, &trampoline) != MH_OK)) {
    return;
  }

  if (enable) {
    Enable();
  }
  else {
    GetModuleInfo(module, moduleHash);
  }
}

MHPatch::~MHPatch() {
  Disable();

  if (minHookCount > 0) {
    if (VerifyModule()) {
      MH_RemoveHook(address);
    }

    if (--minHookCount == 0) {
      MH_Uninitialize();
    }
  }
}

bool MHPatch::Enable(bool force) {
  if (enabled && !force) {
    return true;
  }
  else if (invalid) {
    return false;
  }

  if (!VerifyModule()) {
    return !(invalid = true);
  }

  if (enabled && force) {
    return (enabled = (MH_DisableHook(address) == MH_OK &&
                       MH_EnableHook(address)  == MH_OK));
  }
  else {
    return (enabled = MH_EnableHook(address) == MH_OK);
  }
}

bool MHPatch::Disable(bool unused) {
  if (!enabled) {
    return true;
  }
  else if (invalid) {
    return false;
  }

  if (!VerifyModule()) {
    return !(invalid = true);
  }

  if (MH_DisableHook(address) == MH_OK) {
    return !(enabled = false);
  }
  else {
    return false;
  }
}

// Returns a pointer to a MinHook function trampoline
const void* MHPatch::GetTrampoline() {
  return !invalid ? trampoline : nullptr;
}
#endif

// Ensure the module associated with the patch address is still loaded
bool patch::VerifyModule() {
  if (module == reinterpret_cast<HMODULE>(-1)) {
    GetModuleInfo(module, moduleHash);
    return true;
  }
  else if (InitBaseModule() && module == baseModule) {
    return true;
  }

  HMODULE curModule;
  size_t curHash;
  GetModuleInfo(curModule, curHash);

  return module == curModule && moduleHash == curHash;
}

void patch::GetModuleInfo(HMODULE &moduleOut, size_t &hashOut) {
  if ((moduleOut = GetModuleFromAddress(address))) {
    if (InitBaseModule() && moduleOut == baseModule) {
      // Base module is unloaded last, this sanity checking isn't necessary
      hashOut = 0;
      return;
    }

    auto *header = reinterpret_cast<IMAGE_NT_HEADERS*>(
      reinterpret_cast<uintptr_t>(moduleOut) +
      reinterpret_cast<IMAGE_DOS_HEADER*>(moduleOut)->e_lfanew);

    auto sizeOfCode = header->OptionalHeader.Magic
      != IMAGE_NT_OPTIONAL_HDR64_MAGIC ? header->OptionalHeader.SizeOfCode :
      reinterpret_cast<IMAGE_NT_HEADERS64*>(header)->OptionalHeader.SizeOfCode;

    hashOut = std::hash<ULONGLONG>()(
      (static_cast<ULONGLONG>(header->FileHeader.TimeDateStamp) << 32) + sizeOfCode);
  }
  else {
    hashOut = moduleHash - 1;
  }
}


// Factory functions

// Rewrites an arbitrarily-sized chunk of code or data at the specified address
// expectedBytes (optional) points to a buffer containing the data expected for
// that address for sanity checking
std::shared_ptr<patch> Patch(void *address, size_t patchSize, const void *newBytes,
                             const void *expectedBytes, bool enable) {
  if (!address || !patchSize || !newBytes) {
    return nullptr;
  }

  auto result = std::make_shared<MemPatch>(address, patchSize, newBytes,
                                           expectedBytes, enable);
  if (!result || !result->GetValid()) {
    return nullptr;
  }
  allPatches.push_back(result);

  return result;
}


std::shared_ptr<patch> Patch(void *address, const std::vector<BYTE> &newBytes,
                             const std::vector<BYTE> &expectedBytes, bool enable) {
  return Patch(address, newBytes.size(), newBytes.data(), expectedBytes.size() >=
               newBytes.size() ? expectedBytes.data() : nullptr, enable);
}


// Inserts a jump instruction. Can use MinHook.
std::shared_ptr<patch> PatchFunction(void *address, const void *newFunction,
                                     bool enable) {
  if (!address || !newFunction) {
    return nullptr;
  }

  #ifdef PATCHER_MINHOOK

  auto result = std::make_shared<MHPatch>(address, newFunction, enable);
  if (!result || !result->GetValid()) {
    return nullptr;
  }
  allPatches.push_back(result);

  return result;

  #else

  #pragma pack(push, 1)
  struct {
    BYTE opcode;
    DWORD address;
  } jmp32;
  #pragma pack(pop)

  jmp32.opcode = 0xE9; // JMP near pcrel32
  jmp32.address = static_cast<DWORD>(reinterpret_cast<uintptr_t>(newFunction) -
                                     (reinterpret_cast<uintptr_t>(address) +
                                      sizeof(jmp32)));

  return Patch(address, sizeof(jmp32), &jmp32, nullptr, enable);

  #endif
}

// Inserts/rewrites a call instruction
std::shared_ptr<patch> PatchFunctionCall(void *address, const void *newFunction,
                                         bool enable) {
  if (!address || !newFunction) {
    return nullptr;
  }

  #pragma pack(push, 1)
  struct {
    BYTE opcode;
    DWORD address;
  } call32;
  #pragma pack(pop)

  call32.opcode = 0xE8; // CALL near pcrel32
  call32.address = static_cast<DWORD>(reinterpret_cast<uintptr_t>(newFunction) -
                                      (reinterpret_cast<uintptr_t>(address) +
                                       sizeof(call32)));

  return Patch(address, sizeof(call32), &call32, nullptr, enable);
}


// Replaces virtual function table entry by function address
std::shared_ptr<patch> PatchFunctionVirtual(void *vftableAddress,
                                            const void *oldFunction,
                                            const void *newFunction, bool enable) {
  if (!vftableAddress || !oldFunction || !newFunction) {
    return nullptr;
  }

  void **vftable = static_cast<void**>(vftableAddress);

  // Iterate through the vftable until we find the function we want to replace
  for (int i = 0; i < 1024 && vftable[i]; ++i) {
    if (vftable[i] == oldFunction) {
      return PatchFunctionVirtual(vftableAddress, i, newFunction, enable);
    }
  }

  return nullptr; // Unable to find function in virtual function table
}

// Replaces virtual function table entry by index
std::shared_ptr<patch> PatchFunctionVirtual(void *vftableAddress,
                                            int vftableEntryIndex,
                                            const void *newFunction, bool enable) {
  if (!vftableAddress || !newFunction) {
    return nullptr;
  }

  void **vftable = static_cast<void**>(vftableAddress);

  return Patch(&vftable[vftableEntryIndex], sizeof(void*), &newFunction, nullptr,
               enable);
}


// Patches all references to a global variable/object in base relocation table
bool PatchGlobalReferences(const void *oldGlobalAddress,
                           const void *newGlobalAddress,
                           std::vector<std::shared_ptr<patch>> *out,
                           bool enable, HMODULE module) {
  #pragma pack(push, 1)
  struct TypeOffset {
    WORD offset :12; // Offset, relative to VirtualAddress of the parent block
    WORD type   :4;  // IMAGE_REL_BASED_x - HIGHLOW (x86) or DIR64 (x86_64)
  };
  #pragma pack(pop)

  if (!oldGlobalAddress || !newGlobalAddress) {
    return false;
  }

  if (module == reinterpret_cast<HMODULE>(-1)) {
    if (!InitBaseModule()) {
      return false;
    }
    module = baseModule;
  }
  else if (!module) {
    return false;
  }

  std::vector<std::shared_ptr<patch>> result;
  if (!out) {
    out = &result;
  }

  std::vector<std::shared_ptr<patch>>::iterator first = out->end();
  bool firstInserted = false;

  // Locate the base relocation table via the PE header
  auto *optionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(
    reinterpret_cast<uintptr_t>(module) +
    reinterpret_cast<IMAGE_DOS_HEADER*>(module)->e_lfanew)->OptionalHeader;

  IMAGE_DATA_DIRECTORY *relocDataDir;
  if (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    relocDataDir = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  }
  else if (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    relocDataDir = &reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optionalHeader)
                   ->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  }
  else {
    // Not a valid PE image
    return false;
  }

  if (!relocDataDir->VirtualAddress || !relocDataDir->Size) {
    // No base relocation table
    return false;
  }

  auto *baseRelocTable = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
    module + relocDataDir->VirtualAddress);

  // Relocation table starts with the first block's header
  IMAGE_BASE_RELOCATION *curBlock = baseRelocTable;
  // Iterate through blocks, typically 4096 bytes each, e.g. 0x401000-0x402000
  while (reinterpret_cast<uintptr_t>(curBlock) <
         reinterpret_cast<uintptr_t>(baseRelocTable) + relocDataDir->Size &&
         curBlock->SizeOfBlock) {
    auto *relocArray = reinterpret_cast<TypeOffset*>(
      reinterpret_cast<uintptr_t>(curBlock) + sizeof(IMAGE_BASE_RELOCATION));
    size_t numRelocs = (curBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                       / sizeof(relocArray[0]);

    // Enumerate relocations, find references to the global and replace them
    for (size_t i = 0; i < numRelocs; ++i) {
      void *address = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(module) + curBlock->VirtualAddress +
        relocArray[i].offset);
      size_t ptrSize;

      if (relocArray[i].type == IMAGE_REL_BASED_HIGHLOW) {
        address = reinterpret_cast<void*>(
          static_cast<uintptr_t>(*reinterpret_cast<DWORD*>(address)));
        ptrSize = sizeof(DWORD);
      }
      else if (relocArray[i].type == IMAGE_REL_BASED_DIR64) {
        address = reinterpret_cast<void*>(
          static_cast<uintptr_t>(*reinterpret_cast<ULONGLONG*>(address)));
        ptrSize = sizeof(ULONGLONG);
      }
      else {
        continue;
      }

      if (address == oldGlobalAddress) {
        // Found a reference to the global we want to patch
        std::shared_ptr<patch> curPatch;
        if ((curPatch = Patch(address, ptrSize, &newGlobalAddress,
                              &oldGlobalAddress, enable))) {
          out->emplace_back(std::move(curPatch));

          if (!firstInserted) {
            first = out->end() - 1;
            firstInserted = true;
          }
        }
        else {
          // Clean up any previously created reference patches
          for (auto it = first; it != out->end(); ++it) {
            Unpatch(*it);
          }
          out->erase(first, out->end());
          return false;
        }
      }
    }

    // Set pointer to next relocation table block
    curBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
      reinterpret_cast<uintptr_t>(curBlock) + curBlock->SizeOfBlock);
  }

  return firstInserted;
}


// Helper function to delete patches created by factory functions
bool Unpatch(std::shared_ptr<patch> &which, bool doDelete, bool force) {
  if (!which) {
    return false;
  }

  bool result = which->Disable(force);
  if (doDelete) {
    auto it = std::find(allPatches.begin(), allPatches.end(), which);
    if (it != allPatches.end()) {
      allPatches.erase(it);
    }
    which.reset();
  }
  return result;
}

// Enables all unapplied patches and optionally reapplies enabled patches
bool PatchAll(bool force) {
  bool result = true;
  for (auto it = allPatches.rbegin(); it != allPatches.rend(); ++it) {
    if ((*it)->Enable(force) == false) {
      result = false;
    }
  }
  return result;
}

// Disables and optionally deletes all patches
bool UnpatchAll(bool doDelete, bool force) {
  bool result = true;
  for (auto it = allPatches.rbegin(); it != allPatches.rend(); ++it) {
    if ((*it)->Disable(force) == false) {
      result = false;
    }
  }

  if (doDelete) {
    allPatches.clear();
  }

  return result;
}


// Fixes up a pointer address to correct for module relocation
void* FixPtr(const void *pointer, HMODULE module) {
  if (module == reinterpret_cast<HMODULE>(-1)) {
    if (!InitBaseModule()) {
      return nullptr;
    }
    module = baseModule;
  }
  else if (!module) {
    return nullptr;
  }

  uintptr_t preferredAddress;
  auto it = modulePrefAddr.find(module);
  if (it == modulePrefAddr.end() || !(it->second)) {
    auto *optionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(
      reinterpret_cast<uintptr_t>(module) +
      reinterpret_cast<IMAGE_DOS_HEADER*>(module)->e_lfanew)->OptionalHeader;

    if (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      preferredAddress = optionalHeader->ImageBase;
    }
    else if (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      preferredAddress = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optionalHeader)
                         ->ImageBase;
    }
    else {
      // Not a valid PE image
      return nullptr;
    }

    modulePrefAddr[module] = preferredAddress;
  }
  else {
    preferredAddress = it->second;
  }

  return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(pointer) -
                                 preferredAddress +
                                 reinterpret_cast<uintptr_t>(module));
}


static bool InitBaseModule() {
  return baseModule || (baseModule = GetModuleHandle(nullptr));
}

static HMODULE GetModuleFromAddress(void *address) {
  HMODULE result;
  if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCSTR>(address), &result)) {
    return result;
  }
  else {
    return nullptr;
  }
}

} // namespace Patcher