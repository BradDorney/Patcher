/*
 ***********************************************************************************************************************
 * Copyright (c) 2021, Brad Dorney
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *   disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *   products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***********************************************************************************************************************
 */

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <utility>
#include <limits>
#include <mutex>
#include <memory>

#include <unordered_set>
#include <map>
#include <string>

#include <cstddef>

#include "capstone.h"
#include "Patcher.h"

#if PATCHER_MSVC
# include <intrin.h>
#endif

namespace Patcher {

using namespace Impl;
using namespace Util;
using namespace Registers;

// Internal typedefs

using Status = PatcherStatus;

#pragma pack(push, 1)
// Generic structure of a simple x86 instruction with a 1-byte opcode and one 1-dword operand.
struct Op1_4 {
  uint8  opcode;
  uint32 operand;
};

// 2-byte opcode, one 1-dword operand.
struct Op2_4 {
  uint8  opcode[2];
  uint32 operand;
};

struct Jmp8 {
  uint8 opcode;  // 0xEB (unconditional), 0x7* (conditional)
  int8  operand;
};
#pragma pack(pop)

using Jmp32  = Op1_4; // 0xE9
using Call32 = Op1_4; // 0xE8


// Internal utility functions and classes

// Returns true if any flags are set in mask.
template <typename T1, typename T2> static constexpr bool BitFlagTest(T1 mask, T2 flags) { return (mask & flags) != 0; }

// Aligns a pointer to the given power of 2 alignment.
static void*       PtrAlign(void*       p, size_t align)
  { return       reinterpret_cast<void*>(Align(reinterpret_cast<uintptr>(p), align)); }
static const void* PtrAlign(const void* p, size_t align)
  { return reinterpret_cast<const void*>(Align(reinterpret_cast<uintptr>(p), align)); }

// Returns true if value is at least aligned to the given power of 2 alignment.
template <typename T>
constexpr bool IsAligned(T value, size_t align) { return ((value & static_cast<T>(align - 1)) == 0); }

static bool IsPtrAligned(const void* ptr, size_t align) { return IsAligned(reinterpret_cast<uintptr>(ptr), align); }

// Calculates a hash using std::hash.
template <typename T>  static size_t Hash(const T& src) { return std::hash<T>()(src); }

// Helper functions to append data while incrementing a runner pointer.
static void  CatByte(uint8** ppWriter, uint8 value) { ((*ppWriter)++)[0] = value; }
static void CatBytes(uint8** ppWriter, Span<uint8> src)
#if __INTELLISENSE__  // Workaround for MSVC Intellisense bug with std::copy.
  { }
#else
  { std::copy(src.begin(), src.end(), *ppWriter);  *ppWriter += src.Length(); }
#endif
static void CatBytes(uint8** ppWriter, const uint8* pSrc, uint32 count)
  { memcpy(*ppWriter, pSrc, count);  *ppWriter += count; }

template <typename T>
static void CatValue(uint8** ppWriter, const T& value) { memcpy(*ppWriter, &value, sizeof(T)); *ppWriter += sizeof(T); }

static void AppendString(char** ppWriter, const char*       pSrc)
  { const size_t length = (strlen(pSrc) + 1);  strcpy_s(*ppWriter, length, pSrc);        *ppWriter += length; }
static void AppendString(char** ppWriter, const std::string& src)
  { const size_t length = (src.length() + 1);  strcpy_s(*ppWriter, length, src.data());  *ppWriter += length; }

// Gets the length of an array.
template <typename T, size_t N>  static constexpr uint32 ArrayLen(const T (&src)[N]) { return static_cast<uint32>(N); }

// Translates a Capstone error code to a PatcherStatus.
static Status TranslateCsError(cs_err capstoneError) {
  switch (capstoneError) {
  case CS_ERR_OK:                          return Status::Ok;
  case CS_ERR_MEM:  case CS_ERR_MEMSETUP:  return Status::FailMemAlloc;
  default:                                 return Status::FailDisassemble;
  }
}

// Capstone disassembler helper class.
template <cs_arch CsArchitecture, uint32 CsMode>
class Disassembler {
public:
   Disassembler() : hDisasm_(NULL), refCount_(0) { }
  ~Disassembler() { if (refCount_ != 0) { cs_close(&hDisasm_);  refCount_ = 0; } }

  void Acquire() {
    std::lock_guard<std::mutex> lock(lock_);
    if ((++refCount_ == 1) && (TranslateCsError(cs_open(CsArchitecture, cs_mode(CsMode), &hDisasm_)) != Status::Ok)) {
      refCount_ = 0;
    }
  }

  void Release() {
    std::lock_guard<std::mutex> lock(lock_);
    if ((refCount_ != 0) && (--refCount_ == 0)) {
      cs_close(&hDisasm_);
    }
  }

  std::vector<cs_insn> Disassemble(const void* pAddress, size_t numInsns) const {
    std::vector<cs_insn> out;
    out.reserve(numInsns);

    if (refCount_ != 0) {
      cs_insn*      pInsns = nullptr;
      const size_t  count  = cs_disasm(
        hDisasm_, (const uint8*)(pAddress), sizeof(pInsns->bytes) * numInsns, uintptr(pAddress), numInsns, &pInsns);

      if (pInsns != nullptr) {
        if (GetLastError() == Status::Ok) {
          out.insert(out.end(), pInsns, pInsns + count);
        }
        cs_free(pInsns, count);
      }
    }

    return out;
  }

  Status GetLastError() const { return TranslateCsError(cs_errno(hDisasm_)); }

private:
  csh     hDisasm_;
  uint32  refCount_;

  std::mutex  lock_;
};

// We need to allocate memory such that it can be executed, which requires an extra private heap created with the
// HEAP_CREATE_ENABLE_EXECUTE flag.
class Allocator {
public:
   Allocator() : hHeap_(NULL), refCount_(0) { }
  ~Allocator() { if (hHeap_ != NULL) { HeapDestroy(hHeap_);  hHeap_ = NULL; } }

  void Acquire() {
    std::lock_guard<std::mutex> lock(allocatorLock_);
    ++refCount_;
    if (hHeap_ == NULL) {
      hHeap_ = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    }
  }

  void Release() {
    std::lock_guard<std::mutex> lock(allocatorLock_);
    --refCount_;
    if ((refCount_ == 0) && (hHeap_ != NULL)) {
      HeapDestroy(hHeap_);
      hHeap_ = nullptr;
    }
  }

  void* Alloc(size_t size, size_t align = sizeof(void*)) {
    align = Align(align, sizeof(void*));  // We need at least pointer-size alignment.
    void*const pBaseAlloc    = (hHeap_     != NULL)    ? HeapAlloc(hHeap_, 0, size + align)     : nullptr;
    void*const pAlignedAlloc = (pBaseAlloc != nullptr) ? PtrAlign(PtrInc(pBaseAlloc, 1), align) : nullptr;
    if (pAlignedAlloc != nullptr) {  // Store a pointer to the real allocation just before the aligned output pointer.
      static_cast<void**>(pAlignedAlloc)[-1] = pBaseAlloc;
    }
    return pAlignedAlloc;
  }

  bool Free(void* pMemory) {
    return (pMemory == nullptr) ||
           ((hHeap_ != NULL) && (HeapFree(hHeap_, 0, static_cast<void**>(pMemory)[-1]) == TRUE));
  }

private:
  HANDLE  hHeap_;
  uint32  refCount_;

  std::mutex  allocatorLock_;
};

// Finds the index of the first set bit in a bitmask.  Result is undefined if mask == 0.
#if PATCHER_MSVC && PATCHER_X86
static uint32 BitScanFwd(uint32 mask) { return _tzcnt_u32(mask); }
#elif PATCHER_MSVC
static uint32 BitScanFwd(uint32 mask) { unsigned long index;  _BitScanForward(&index, mask);  return index; }
#elif PATCHER_GXX
static uint32 BitScanFwd(uint32 mask) { return __builtin_ctz(mask); }
#else
static uint32 BitScanFwd(uint32 mask) {
  uint32 index;
  if (mask != 0) {
    for (index = 0; (mask & 1) == 0; mask >>= 1, ++index);
  }
  return index;
}
#endif

// Internal constants

// x86 fetches instructions on 16-byte boundaries.  Allocated code should be aligned on these boundaries in memory.
static constexpr uint32 CodeAlignment      = 16;
// Max instruction size on modern x86 is 15 bytes.
static constexpr uint32 MaxInstructionSize = 15;
// Worst-case scenario is the last byte overwritten being the start of a MaxInstructionSize-sized instruction.
static constexpr uint32 MaxOverwriteSize   = (sizeof(Jmp32) + MaxInstructionSize - 1);

// Max size in bytes low-level hook trampoline code is expected to require.
static constexpr uint32 MaxLowLevelHookSize = Align(160, CodeAlignment);
// Max size in bytes functor thunk code is expected to require.
static constexpr size_t MaxFunctorThunkSize = Align(32, CodeAlignment);

static constexpr uint32 OpenThreadFlags =
  (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION);

static constexpr uint32 ExecutableProtectFlags =
  (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
static constexpr uint32 ReadOnlyProtectFlags   = (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE);

// Internal globals

static Disassembler<CS_ARCH_X86, CS_MODE_32>  g_disasm;

static Allocator   g_allocator;
static std::mutex  g_codeThreadLock;

// =====================================================================================================================
// Gets the index of the first set bit in a bitmask through an output parameter, and returns (mask != 0).
static bool BitScanFwdIter(
  uint32*  pIndex,
  uint32   mask)
{
  bool result = false;
  *pIndex = BitScanFwd(mask);
  if (mask != 0) {
    result = (mask != 0);
  }
  return result;
}

// =====================================================================================================================
// Returns the number of set bits in a bitmask.
static uint32 PopCount(
  uint32  x)
{
  x = x - ((x >> 1u) & 0x55555555u);
  x = (x & 0x33333333u) + ((x >> 2u) & 0x33333333u);
  return (((x + (x >> 4u)) & 0x0F0F0F0Fu) * 0x01010101u) >> ((sizeof(uint32) - 1u) * 8u);
}

// =====================================================================================================================
// Helper function to get the base load address of the module containing pAddress.
// Note that heap memory does not belong to a module, in which case this function returns NULL.
static HMODULE GetModuleFromAddress(
  const void*  pAddress,
  bool         addReference = false)
{
  const DWORD Flags = (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       (addReference ? 0 : GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT));
  HMODULE hModule = NULL;
  return (GetModuleHandleExA(Flags, static_cast<LPCSTR>(pAddress), &hModule) == TRUE) ? hModule : NULL;
}

// =====================================================================================================================
static uint32 CalculateModuleHash(
  void*  hModule)
{
  size_t result = 0;
  const auto*const pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(GetModuleFromAddress(hModule));

  if ((pDosHeader != nullptr) && (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)) {
    const auto&  ntHeader         = *PtrInc<IMAGE_NT_HEADERS*>(hModule, pDosHeader->e_lfanew);
    const auto&  optionalHeader   = ntHeader.OptionalHeader;
    const auto&  optionalHeader64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64&>(optionalHeader);

    const bool isPe32 = (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    const bool isPe64 = (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    if (isPe32 || isPe64) {
      result           = Hash(ntHeader.FileHeader.TimeDateStamp);
      result ^= isPe64 ? Hash(optionalHeader64.CheckSum)                : Hash(optionalHeader.CheckSum);
      result ^= isPe64 ? Hash(optionalHeader64.SizeOfInitializedData)   : Hash(optionalHeader.SizeOfInitializedData);
      result ^= isPe64 ? Hash(optionalHeader64.SizeOfUninitializedData) : Hash(optionalHeader.SizeOfUninitializedData);
      result ^= isPe64 ? Hash(optionalHeader64.SizeOfCode)              : Hash(optionalHeader.SizeOfCode);
      result ^= isPe64 ? Hash(optionalHeader64.SizeOfImage)             : Hash(optionalHeader.SizeOfImage);
      result ^= isPe64 ? Hash(optionalHeader64.ImageBase)               : Hash(optionalHeader.ImageBase);
      result ^= isPe64 ? Hash(optionalHeader64.AddressOfEntryPoint)     : Hash(optionalHeader.AddressOfEntryPoint);
    }
  }

  return (sizeof(size_t) <= sizeof(uint32)) ?
         static_cast<uint32>(result) : static_cast<uint32>((static_cast<uint64>(result) >> 32) ^ (result & 0xFFFFFFFF));
}

// =====================================================================================================================
static IMAGE_DATA_DIRECTORY* GetDataDirectory(
  void*  hModule,
  uint32 index)    // IMAGE_DIRECTORY_ENTRY_xx
{
  IMAGE_DATA_DIRECTORY* pDataDir   = nullptr;
  const auto*const      pDosHeader = static_cast<const IMAGE_DOS_HEADER*>(hModule);

  if ((pDosHeader != nullptr) && (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)) {
    auto& optionalHeader   = PtrInc<IMAGE_NT_HEADERS*>(hModule, pDosHeader->e_lfanew)->OptionalHeader;
    auto& optionalHeader64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64&>(optionalHeader);

    const uint32 numDataDirs =
      (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? optionalHeader.NumberOfRvaAndSizes   :
      (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? optionalHeader64.NumberOfRvaAndSizes : 0;

    if (numDataDirs > index) {
      pDataDir = (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? &optionalHeader64.DataDirectory[index]
                                                                         : &optionalHeader.DataDirectory[index];
    }
  }

  return pDataDir;
}

// =====================================================================================================================
PatchContext::PatchContext(
  const char*  pModuleName,
  bool         loadModule)
  :
  hModule_((loadModule && (pModuleName != nullptr)) ? LoadLibraryA(pModuleName) : GetModuleHandleA(pModuleName)),
  hasModuleRef_(loadModule && (pModuleName != nullptr) && (hModule_ != NULL)),
  moduleRelocDelta_(0),
  moduleHash_(CalculateModuleHash(hModule_)),
  status_(Status::FailInvalidModule)
{
  g_disasm.Acquire();
  g_allocator.Acquire();
  InitModule();
}

// =====================================================================================================================
PatchContext::PatchContext(
  const void*  hModule,
  bool         addReference)
  :
  hModule_(GetModuleFromAddress(hModule, addReference)),
  hasModuleRef_(addReference && (hModule_ != NULL)),
  moduleRelocDelta_(0),
  moduleHash_(CalculateModuleHash(hModule_)),
  status_(Status::FailInvalidModule)
{
  g_disasm.Acquire();
  g_allocator.Acquire();
  InitModule();
}

// =====================================================================================================================
PatchContext::~PatchContext() {
  RevertAll();
  UnlockThreads();
  ReleaseModule();
  g_allocator.Release();
  g_disasm.Release();
}

// =====================================================================================================================
Status PatchContext::ResetStatus() {
  if (status_ != Status::FailModuleUnloaded) {
    status_ = Status::Ok;
  }
  return status_;
}

// =====================================================================================================================
void PatchContext::InitModule() {
  const auto*const pDosHeader = static_cast<const IMAGE_DOS_HEADER*>(hModule_);

  if ((pDosHeader != nullptr) && (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)) {
    // Calculate the module's base relocation delta.
    const auto& peHeader = *PtrInc<IMAGE_NT_HEADERS*>(hModule_, pDosHeader->e_lfanew);

    if (peHeader.Signature == IMAGE_NT_SIGNATURE) {
      if (peHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        moduleRelocDelta_ = PtrDelta(hModule_, reinterpret_cast<const void*>(peHeader.OptionalHeader.ImageBase));
        status_ = Status::Ok;
      }
      else if (peHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto& optionalHeader64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64&>(peHeader.OptionalHeader);
        moduleRelocDelta_ = PtrDelta(hModule_, reinterpret_cast<const void*>(optionalHeader64.ImageBase));
        status_ = Status::Ok;
      }
    }
  }
}

// =====================================================================================================================
Status PatchContext::SetModule(
  const char* pModuleName,
  bool        loadModule)
{
  if (GetModuleHandleA(pModuleName) != hModule_) {
    RevertAll();
    UnlockThreads();
    ReleaseModule();

    status_       = Status::FailInvalidModule;
    hModule_      = (loadModule && (pModuleName != nullptr)) ? LoadLibraryA(pModuleName): GetModuleHandleA(pModuleName);
    hasModuleRef_ =  loadModule && (pModuleName != nullptr) && (hModule_ != NULL);
    moduleHash_   = CalculateModuleHash(hModule_);
    moduleRelocDelta_ = 0;

    InitModule();
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::SetModule(
  const void* hModule,
  bool        addReference)
{
  if (GetModuleFromAddress(hModule) != hModule_) {
    RevertAll();
    UnlockThreads();
    ReleaseModule();

    status_           = Status::FailInvalidModule;
    hModule_          = GetModuleFromAddress(hModule, addReference);
    hasModuleRef_     = addReference && (hModule_ != NULL);
    moduleHash_       = CalculateModuleHash(hModule_);
    moduleRelocDelta_ = 0;

    InitModule();
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::Memcpy(
  TargetPtr    pAddress,
  const void*  pSrc,
  size_t       size)
{
  if ((status_ == Status::Ok) && ((pAddress == nullptr) || (pSrc == nullptr) || (size == 0))) {
    status_ = Status::FailInvalidPointer;
  }

  pAddress = MaybeFixTargetPtr(pAddress);
  const uint32 oldAttr = BeginDeProtect(pAddress, size);

  if (status_ == Status::Ok) {
    memcpy(pAddress, pSrc, size);
    EndDeProtect(pAddress, size, oldAttr);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::Memset(
  TargetPtr  pAddress,
  uint8      value,
  size_t     count)
{
  if ((status_ == Status::Ok) && ((pAddress == nullptr) || (count == 0))) {
    status_ = Status::FailInvalidPointer;
  }

  pAddress = MaybeFixTargetPtr(pAddress);
  const uint32 oldAttr = BeginDeProtect(pAddress, count);

  if (status_ == Status::Ok) {
    memset(pAddress, value, count);
    EndDeProtect(pAddress, count, oldAttr);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::WriteNop(
  TargetPtr  pAddress,
  size_t     size)
{
  if ((status_ == Status::Ok) && (pAddress == nullptr)) {
    status_ = Status::FailInvalidPointer;
  }

  pAddress = MaybeFixTargetPtr(pAddress);

#if PATCHER_X86
  static constexpr uint8 NopTable[][10] = {
    { 0x90,                                                       },
    { 0x66, 0x90,                                                 },
    { 0x0F, 0x1F, 0x00,                                           },
    { 0x0F, 0x1F, 0x40, 0x00,                                     },
    { 0x0F, 0x1F, 0x44, 0x00, 0x00,                               },
    { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,                         },
    { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,                   },
    { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,             },
    { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,       },
    { 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, },
  };
#else
  static constexpr uint8 NopTable[][1] = { };
  status_ = Status::FailUnsupported;
#endif

  if ((status_ == Status::Ok) && (size == 0)) {
    // If size == 0, then overwrite the whole instruction at pAddress.
    const auto& insns = g_disasm.Disassemble(pAddress, 1);
    status_ = (insns.size() != 0) ? g_disasm.GetLastError() : Status::FailDisassemble;

    if (status_ == Status::Ok) {
      size = insns[0].size;
    }
  }

  const uint32 oldAttr = BeginDeProtect(pAddress, size);

  if (status_ == Status::Ok) {
    for (size_t remain = size, copySize; (copySize = (std::min)(ArrayLen(NopTable), remain)) != 0; remain -= copySize) {
      memcpy(PtrInc(pAddress, (remain - copySize)), &NopTable[copySize - 1], copySize);
    }
    EndDeProtect(pAddress, size, oldAttr);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::Revert(
  TargetPtr  pAddress)
{
  Status tmpStatus = Status::Ok;
  std::swap(tmpStatus, status_);

  const auto it = historyAt_.find(MaybeFixTargetPtr(pAddress));

  if (it != historyAt_.end()) {
    const PatchInfo& entry = *it->second;

    Memcpy(entry.pAddress, entry.oldData.Data(), entry.oldData.Size());

    if (status_ == Status::Ok) {
      if (entry.pTrackedAlloc != nullptr) {
        AdvanceThreads(entry.pTrackedAlloc, entry.trackedAllocSize);

        // If Memcpy failed, this won't get cleaned up until the allocation heap is destroyed.
        g_allocator.Free(entry.pTrackedAlloc);

        if (entry.pFunctorObj != nullptr) {
          assert(entry.pfnFunctorDeleter != nullptr);
          entry.pfnFunctorDeleter(entry.pFunctorObj);
        }
      }

      history_.erase(it->second);
      historyAt_.erase(it);
    }
  }

  if ((status_ == Status::Ok) && (history_.empty() == false)) {
    std::swap(tmpStatus, status_);
  }
  else {
    tmpStatus = status_;
  }

  return tmpStatus;
}

// =====================================================================================================================
Status PatchContext::RevertExports() {
  IMAGE_DATA_DIRECTORY*const pExportDataDir = GetDataDirectory(hModule_, IMAGE_DIRECTORY_ENTRY_EXPORT);
  if (pExportDataDir != nullptr) {
    status_ = Revert(pExportDataDir);
  }
  return status_;
}

// =====================================================================================================================
Status PatchContext::RevertAll() {
  Status endStatus = status_ = Status::Ok;

  for (const auto& entry: history_) {
    Memcpy(entry.pAddress, entry.oldData.Data(), entry.oldData.Size());

    if (((status_ == Status::Ok) || (status_ == Status::FailModuleUnloaded)) && (entry.pTrackedAlloc != nullptr)) {
      AdvanceThreads(entry.pTrackedAlloc, entry.trackedAllocSize);

      // If Memcpy failed, this won't get cleaned up until the trampoline allocation heap is destroyed.
      g_allocator.Free(entry.pTrackedAlloc);

      if (entry.pFunctorObj != nullptr) {
        assert(entry.pfnFunctorDeleter != nullptr);
        entry.pfnFunctorDeleter(entry.pFunctorObj);
      }
    }

    if (status_ != Status::Ok) {
      endStatus = status_;
      status_   = Status::Ok;
    }
  }

  if (status_ == Status::Ok) {
    history_.clear();
    historyAt_.clear();
  }

  return endStatus;
}

// =====================================================================================================================
Status PatchContext::ReleaseModule() {
  if (hasModuleRef_) {
    if ((FreeLibrary(static_cast<HMODULE>(hModule_)) == FALSE) && (status_ == Status::Ok)) {
      status_ = Status::FailModuleUnloaded;
    }
    if ((status_ == Status::Ok) && (CalculateModuleHash(hModule_) != moduleHash_)) {
      status_ = Status::FailModuleUnloaded;
    }
    hasModuleRef_ = false;
  }

  return status_;
}

// =====================================================================================================================
static constexpr uintptr GetProgramCounter(
  const CONTEXT& context)
{
#if PATCHER_X86_32
  return static_cast<uintptr>(context.Eip);
#elif PATCHER_X86_64
  return static_cast<uintptr>(context.Rip);
#else
  return 0;
#endif
}

// =====================================================================================================================
Status PatchContext::LockThreads() {
  g_codeThreadLock.lock();

  // Create a snapshot of current process threads.
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

  if (hSnapshot != INVALID_HANDLE_VALUE) {
    const auto thisProcessId = GetCurrentProcessId();
    const auto thisThreadId  = GetCurrentThreadId();

    THREADENTRY32 entry = { };
    entry.dwSize = sizeof(entry);

    for (auto x = Thread32First(hSnapshot, &entry); (status_ == Status::Ok) && x; x = Thread32Next(hSnapshot, &entry)) {
      if ((entry.dwSize             >  offsetof(THREADENTRY32, th32OwnerProcessID)) &&
          (entry.th32OwnerProcessID == thisProcessId)                               &&
          (entry.th32ThreadID       != thisThreadId))
      {
        HANDLE hThread = OpenThread(OpenThreadFlags, FALSE, entry.th32ThreadID);
        if (hThread != NULL) {
          SuspendThread(hThread);

          CONTEXT ctx;
          ctx.ContextFlags = CONTEXT_CONTROL;
          uintptr pc = 0;

          if (GetThreadContext(hThread, &ctx)) {
            pc = GetProgramCounter(ctx);
          }
          else {
            status_ = Status::FailLockThreads;
          }

          frozenThreads_.emplace_back(entry.th32ThreadID, pc);
          CloseHandle(hThread);
        }
        else {
          status_ = Status::FailLockThreads;
        }
      }
    }

    CloseHandle(hSnapshot);
  }
  else {
    status_ = Status::FailLockThreads;
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::UnlockThreads() {
  for (const auto& threadInfo : frozenThreads_) {
    HANDLE hThread = OpenThread(OpenThreadFlags, FALSE, threadInfo.first);
    if (hThread != NULL) {
      ResumeThread(hThread);
      CloseHandle(hThread);
    }
  }

  const bool needsUnlock = (frozenThreads_.empty() == false);
  frozenThreads_.clear();

  if (needsUnlock) {
    const bool ignored = g_codeThreadLock.try_lock();
    g_codeThreadLock.unlock();
  }

  return status_;
}

// =====================================================================================================================
static uintptr AdvanceThread(
  HANDLE       hThread,
  const void*  pSkippedMemory,
  size_t       skippedMemorySize)
{
  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_CONTROL;

  int  oldPriority = THREAD_PRIORITY_NORMAL;
  bool setPriority = false;

  for (uint32 i = 0; ((GetThreadContext(hThread, &ctx) != 0) && (i < UINT_MAX)); ++i) {
    const void*const pPc = reinterpret_cast<void*>(GetProgramCounter(ctx));

    if ((pPc >= pSkippedMemory) && (pPc < PtrInc(pSkippedMemory, skippedMemorySize))) {
      if (setPriority == false) {
        // Set the thread's priority to highest to help guarantee we context switch to it when we yield.
        oldPriority = GetThreadPriority(hThread);
        setPriority = (oldPriority >= THREAD_PRIORITY_HIGHEST) || SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
      }

      // Yield to the other thread to allow it to continue.
      ResumeThread(hThread);
      Sleep(0);
      SuspendThread(hThread);
    }
    else {
      // We're outside of the skip region.
      break;
    }
  }

  if (setPriority && (oldPriority < THREAD_PRIORITY_HIGHEST)) {
    SetThreadPriority(hThread, oldPriority);
  }

  return GetProgramCounter(ctx);
}

// =====================================================================================================================
// Prevent race conditions between writing code and executing it.  This is a no-op if LockThreads() hasn't been called.
Status PatchContext::AdvanceThreads(
  void*   pAddress,
  size_t  size)
{
  const uintptr address = reinterpret_cast<uintptr>(pAddress);

  for (auto& threadInfo : frozenThreads_) {
    if ((threadInfo.second >= address) && (threadInfo.second < (address + size))) {
      HANDLE hThread = OpenThread(OpenThreadFlags, FALSE, threadInfo.first);

      if (hThread != NULL) {
        threadInfo.second = AdvanceThread(hThread, pAddress, size);
        CloseHandle(hThread);
      }
      else {
        status_ = Status::FailLockThreads;
        break;
      }
    }

    if ((threadInfo.second >= address) && (threadInfo.second < (address + size))) {
      status_ = Status::FailLockThreads;
      break;
    }
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::Touch(
  TargetPtr  pAddress,
  size_t     size)
{
  pAddress = MaybeFixTargetPtr(pAddress);

  if (status_ == Status::Ok) {
    // Make a copy of the original data if it hasn't been tracked already so we can revert it later.
    auto it = historyAt_.find(pAddress);
    if (it == historyAt_.end()) {
      const size_t oldSize = history_.size();
      history_.emplace_front(PatchInfo{ pAddress, ByteArray<StorageSize>(pAddress, size) });

      if ((history_.size() == oldSize) || (historyAt_.emplace(pAddress, history_.begin()).first == historyAt_.end())) {
        status_ = Status::FailMemAlloc;
      }
    }
    else {
      PatchInfo& entry = *it->second;
      if (entry.oldData.Size() < size) {
        // Merge the original tracked data with the extra bytes we also need to track.
        entry.oldData.Append(PtrInc(pAddress, entry.oldData.Size()), (size - entry.oldData.Size()));
      }
    }
  }

  return status_;
}

// =====================================================================================================================
uint32 PatchContext::BeginDeProtect(
  void*   pAddress,
  size_t  size)
{
  DWORD attr = 0;

  if ((status_ == Status::Ok) && (CalculateModuleHash(hModule_) != moduleHash_)) {
    status_ = Status::FailModuleUnloaded;
  }

  if (status_ == Status::Ok) {
    const HMODULE hDstModule = GetModuleFromAddress(pAddress);
    // Note:  Heap-allocated memory isn't associated with any module, in which case hModule will be set to nullptr.
    // Patching modules other than the one associated with this context is an error.
    if ((hDstModule != nullptr) && (hDstModule != hModule_)) {
      status_ = Status::FailInvalidPointer;
    }
  }

  if (status_ == Status::Ok) {
    // Query memory page protection information to determine how we need to barrier around making this memory writable.
    MEMORY_BASIC_INFORMATION memInfo;

    if ((VirtualQuery(pAddress, &memInfo, sizeof(memInfo)) > offsetof(MEMORY_BASIC_INFORMATION, Protect)) &&
        (memInfo.State  == MEM_COMMIT) &&
        (memInfo.Protect > PAGE_NOACCESS))
    {
      attr = memInfo.Protect;
    }
    else {
      status_ = Status::FailDeProtectMem;
    }
  }

  if ((status_ == Status::Ok) && BitFlagTest(attr, ExecutableProtectFlags)) {
    // If we froze threads via LockThreads(), we can barrier around race conditions between executing code and writing.
    AdvanceThreads(pAddress, size);
  }

  if ((status_ == Status::Ok) && BitFlagTest(attr, ReadOnlyProtectFlags)) {
    // Deprotect non-readable and/or non-writable memory.
    status_ = (VirtualProtect(pAddress, size, PAGE_EXECUTE_READWRITE, &attr) ||
               VirtualProtect(pAddress, size, PAGE_EXECUTE_WRITECOPY, &attr)) ? Status::Ok : Status::FailDeProtectMem;
  }

  if (status_ == Status::Ok) {
    // Make a copy of the original data if it hasn't been tracked already so we can revert it later.
    Touch(pAddress, size);
  }

  return static_cast<uint32>(attr);
}

// =====================================================================================================================
void PatchContext::EndDeProtect(
  void*   pAddress,
  size_t  size,
  uint32  oldAttr)
{
  if (status_ == Status::Ok) {
    if (BitFlagTest(oldAttr, ReadOnlyProtectFlags)) {
      // Reprotect non-readable and/or non-writable memory.
      VirtualProtect(pAddress, size, oldAttr, reinterpret_cast<DWORD*>(&oldAttr));
    }

    if (BitFlagTest(oldAttr, ExecutableProtectFlags)) {
      // Flush instruction cache of executable memory.
      FlushInstructionCache(static_cast<HMODULE>(hModule_), pAddress, size);
    }
  }
}

// =====================================================================================================================
Status PatchContext::ReplaceReferencesToGlobal(
  TargetPtr            pOldGlobal,
  size_t               size,
  const void*          pNewGlobal,
  std::vector<void*>*  pRefsOut)
{
  struct RelocInfo {
    uint16  offset : 12;  // Offset, relative to VirtualAddress of the parent block
    uint16  type   :  4;  // IMAGE_REL_BASED_x - HIGHLOW (x86_32) or DIR64 (x86_64)
  };

  if ((status_ == Status::Ok) && (pOldGlobal == nullptr) || (pNewGlobal == nullptr)) {
    status_ = Status::FailInvalidPointer;
  }
  pOldGlobal = MaybeFixTargetPtr(pOldGlobal);

  if (size == 0) {
    size = 1;
  }

  std::vector<void*> localRefsOut;
  if (pRefsOut == nullptr) {
    pRefsOut = &localRefsOut;
  }
  const size_t startIndex = pRefsOut->size();

  // Locate the base relocation table via the PE header.
  // Note that we will ignore the "relocations stripped" bit in the PE flags - some hand-patched exes hack that flag to
  // soft-disable base relocations, even though the .reloc section exists.
  const IMAGE_DATA_DIRECTORY*const pRelocDataDir = GetDataDirectory(hModule_, IMAGE_DIRECTORY_ENTRY_BASERELOC);

  if ((status_ == Status::Ok) &&
      ((pRelocDataDir == nullptr) || (pRelocDataDir->VirtualAddress == 0) || (pRelocDataDir->Size == 0)))
  {
    // No base relocation table, or not a valid PE image.
    status_ = Status::FailInvalidModule;
  }

  if (status_ == Status::Ok) {
    const auto*const pRelocTable = PtrInc<IMAGE_BASE_RELOCATION*>(hModule_, pRelocDataDir->VirtualAddress);
    const auto*      pCurBlock   = pRelocTable;

    // Iterate through relocation table blocks.  Each block typically represents 4096 bytes, e.g. 0x401000-0x402000.
    while ((status_ == Status::Ok) &&
           (static_cast<const void*>(pCurBlock) < PtrInc(pRelocTable, pRelocDataDir->Size)) &&
           (pCurBlock->SizeOfBlock != 0))
    {
      const auto*const pRelocArray = PtrInc<RelocInfo*>(pCurBlock, sizeof(IMAGE_BASE_RELOCATION));
      const size_t     numRelocs   = ((pCurBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RelocInfo));

      // Iterate over relocations, find references to the global and replace them.
      for (size_t i = 0; ((status_ == Status::Ok) && (i < numRelocs)); ++i) {
        void*const   ppAddress = (static_cast<uint8*>(hModule_) + pCurBlock->VirtualAddress + pRelocArray[i].offset);
        const void*  pAddress  = nullptr;
        size_t       ptrSize   = 0;

        const auto it           = historyAt_.find(ppAddress);
        auto*const pHistoryData = (it != historyAt_.end()) ? &it->second->oldData : nullptr;

        if (pRelocArray[i].type == IMAGE_REL_BASED_HIGHLOW) {
          ptrSize  = 4;
          pAddress = reinterpret_cast<const void*>(*static_cast<uint32*>(
            ((pHistoryData != nullptr) && (pHistoryData->Size() == ptrSize)) ? pHistoryData->Data() : ppAddress));
        }
        else if (pRelocArray[i].type == IMAGE_REL_BASED_DIR64) {
          ptrSize  = 8;
          pAddress = reinterpret_cast<const void*>(*static_cast<uint64*>(
            ((pHistoryData != nullptr) && (pHistoryData->Size() == ptrSize)) ? pHistoryData->Data() : ppAddress));
        }

        if ((pAddress != nullptr) && (ptrSize != 0)) {
          const size_t delta = PtrDelta(pAddress, pOldGlobal);

          if ((pAddress >= pOldGlobal) && (delta < size)) {
            // Found a reference to the global we want to replace.  Patch it.
            const uint64 newAddress = (reinterpret_cast<uintptr>(pNewGlobal) + delta);
            if ((newAddress >> (ptrSize * 8)) == 0) {
              Memcpy(ppAddress, &newAddress, ptrSize);

              if (status_ == Status::Ok) {
                pRefsOut->push_back(ppAddress);
              }
            }
            else {
              // New pointer size is larger than the one we're trying to replace.
              status_ = Status::FailInvalidPointer;
            }
          }
        }
      }

      // Set pointer to next relocation table block.
      pCurBlock = PtrInc<IMAGE_BASE_RELOCATION*>(pCurBlock, pCurBlock->SizeOfBlock);
    }
  }

  if (status_ != Status::Ok) {
    for (auto it = (pRefsOut->begin() + startIndex); it != pRefsOut->end(); Revert(*(it++)));
    pRefsOut->erase((pRefsOut->begin() + startIndex), pRefsOut->end());
  }

  return status_;
}

// =====================================================================================================================
// Creates a thunk to call FunctionPtr::InvokeFunctor().
static void* CreateFunctorThunk(
  const FunctionPtr&  pfnCallback,               // [in]  FunctionPtr that has an associated functor.
  void*               pPlacementAddr = nullptr)  // [in]  (Optional) Pointer to pre-allocated memory to write out to.
{
  assert(pfnCallback.Functor() != nullptr);

  void* pMemory =
    (pPlacementAddr != nullptr) ? pPlacementAddr : g_allocator.Alloc(MaxFunctorThunkSize, CodeAlignment);

  if (pMemory != nullptr) {
    auto* pWriter = static_cast<uint8*>(pMemory);

    const uintptr     functorAddr = reinterpret_cast<uintptr>(pfnCallback.Functor());
    const RtFuncSig&  sig         = pfnCallback.Signature();

    size_t numRegisterSizeParams = 0;  // Excluding pFunctor and pReturnAddress
    for (uint32 i = 2; i < sig.numParams; (sig.pParamSizes[i++] <= RegisterSize) ? ++numRegisterSizeParams : 0);

    // pfnCallback.Pfn() is always cdecl;  Signature().convention refers to the original function Pfn() wraps.
    // We need to translate from the input calling convention to cdecl by pushing any register args used by the input
    // convention to the stack, then push the functor obj address and do the call, then do any expected stack cleanup.
    auto WriteCall = [&pWriter, &pfnCallback, functorAddr] {
      CatValue(&pWriter,  Op1_4{ 0x68, functorAddr });                                           // push pFunctor
      CatValue(&pWriter, Call32{ 0xE8, PcRelPtr(pWriter, sizeof(Call32), pfnCallback.Pfn()) });  // call pFunction
    };

    auto WriteCallAndCalleeCleanup = [&pWriter, &sig, &WriteCall, functorAddr] {
      const auto stackDelta = static_cast<int32>(sig.totalParamSize);
      if (sig.returnSize > (RegisterSize * 2)) {
        pWriter = nullptr;  // ** TODO need to handle oversized return types
      }
      else {
        WriteCall();
        CatBytes(&pWriter, { 0x8B, 0x4C, 0x24, 0x04 });                        // mov ecx, [esp + 4]
        if (stackDelta <= INT8_MAX) {
          CatBytes(&pWriter, { 0x83, 0xC4, static_cast<uint8>(stackDelta) });  // add esp, i8
        }
        else {
          CatBytes(&pWriter, { 0x81, 0xC4, });                                 // add esp, i32
          CatValue(&pWriter, stackDelta);
        }
        CatBytes(&pWriter, { 0xFF, 0xE1 });                                    // jmp ecx
      }
    };

    switch (sig.convention) {
#if PATCHER_X86_32
    case Call::Cdecl:
      WriteCall();
      CatBytes(&pWriter, { 0x83, 0xC4, 0x04,  // add esp, 0x4
                           0xC3 });           // retn
      break;

    case Call::Stdcall:
      WriteCallAndCalleeCleanup();
      break;

    case Call::Thiscall:
      // MS thiscall puts arg 1 in ECX.  If the arg exists, put it on the stack.
      CatByte(&pWriter, 0x5A);                                           //  pop  edx
      (numRegisterSizeParams >= 1) ? CatBytes(&pWriter, { 0x51, 0x52 })  // (push ecx)
                                   :  CatByte(&pWriter,   0x52);         //  push edx
      WriteCallAndCalleeCleanup();
      break;

    case Call::Fastcall:
      // MS fastcall puts the first 2 register-sized args in ECX and EDX.  If the args exist, put them on the stack.
      (numRegisterSizeParams >= 2) ? CatBytes(&pWriter, { 0x87, 0x14, 0x24 })  // (xchg edx, [esp]) or
                                   :  CatByte(&pWriter,   0x5A);               // (pop  edx)
      (numRegisterSizeParams >= 1) ? CatBytes(&pWriter, { 0x51, 0x52 })        // (push ecx)
                                   :  CatByte(&pWriter,   0x52);               //  push edx
      WriteCallAndCalleeCleanup();
      break;
#endif

    default:
      // Unknown or unsupported calling convention.
      pWriter = nullptr;
      break;
    }

    if (pWriter == nullptr) {
      if (pPlacementAddr == nullptr) {
        g_allocator.Free(pMemory);
      }
      pMemory = nullptr;
    }
    else {
      assert(PtrDelta(pWriter, pMemory) <= MaxFunctorThunkSize);
    }
  }

  return pMemory;
}

// =====================================================================================================================
static void CopyInstructions(
  uint8**         ppWriter,
  const cs_insn*  pInsns,
  size_t*         pCount,
  uint8*          pOverwrittenSize,
  uint8           offsetLut[MaxOverwriteSize])
{
  assert(
    (ppWriter != nullptr) && (pInsns != nullptr) && (pCount != nullptr) && (*pCount != 0) && (offsetLut != nullptr));

  uint8*const  pBegin     = *ppWriter;
  size_t  curOldOffset    = 0;
  size_t  count           = *pCount;
  uint8   overwrittenSize = *pOverwrittenSize;
  std::vector<std::pair<uint32*, uint8>> internalRelocs;

  for (size_t i = 0; i < count; ++i) {
    const auto& insn  = pInsns[i];
    const auto& bytes = insn.bytes;

    ptrdiff_t pcRelTarget = 0;

    // Store mapping of the original instruction to the offset of the new instruction we're writing.
    offsetLut[curOldOffset] = static_cast<uint8>(PtrDelta(*ppWriter, pBegin));
    curOldOffset += insn.size;

    // Instructions which use PC-relative operands need to be changed to their 32-bit forms and fixed up.
    // Call
    if (bytes[0] == 0xE8) {
      CatByte(ppWriter, 0xE8);
      const auto*const pCall = reinterpret_cast<const Call32*>(&bytes[0]);
      pcRelTarget = pCall->operand;
    }
    // Jump
    else if (bytes[0] == 0xE9) {
      CatByte(ppWriter, 0xE9);
      const auto*const pJmp = reinterpret_cast<const Jmp32*>(&bytes[0]);
      pcRelTarget = pJmp->operand;
    }
    else if (bytes[0] == 0xEB) {
      CatByte(ppWriter, 0xE9);
      pcRelTarget = static_cast<int8>(bytes[1]);
    }
    // Conditional jump
    else if ((bytes[0] == 0x0F) && (bytes[1] >= 0x80) && (bytes[1] <= 0x8F)) {
      CatBytes(ppWriter, { 0x0F, bytes[1] });
      const auto*const pJmp = reinterpret_cast<const Op2_4*>(&bytes[0]);
      pcRelTarget = pJmp->operand;
    }
    else if ((bytes[0] >= 0x70) && (bytes[0] <= 0x7F)) {
      CatBytes(ppWriter, { 0x0F, static_cast<uint8>(bytes[0] + 0x10) });
      pcRelTarget = static_cast<int8>(bytes[1]);
    }
    // Loop, jump if ECX == 0
    else if ((bytes[0] >= 0xE0) && (bytes[0] <= 0xE3)) {
      // LOOP* and JECX have no 32-bit operand versions, so we have to use multiple jump instructions to emulate it.
      CatByte(ppWriter, bytes[0]);

#pragma pack(push, 1)
      struct {
        uint8  operand     = sizeof(skipTarget);       // (byte)
        Jmp8   skipTarget  = { 0xEB, sizeof(Jmp32) };  // jmp short (sizeof(Jmp32))
        uint8  jmp32Opcode = 0xE9;                     // jmp near (dword)
      } static constexpr CodeChunk;
#pragma pack(pop)
      static_assert((sizeof(uint8) + sizeof(CodeChunk) + sizeof(uint32)) <= MaxInstructionSize,
        "Set of instructions for LOOP/JECX near emulation is too large.");

      CatValue(ppWriter, CodeChunk);
      pcRelTarget = bytes[1];
    }

    if (pcRelTarget == 0) {
      // Just copy instructions without PC rel operands verbatim.
      CatBytes(ppWriter, &bytes[0], insn.size);
    }
    else {
      // Instructions with PC rel operands must be fixed up.  The new opcode has already been written.
      const auto target = static_cast<uintptr>(pcRelTarget + insn.address + insn.size);
      const auto offset = static_cast<ptrdiff_t>(target - pInsns[0].address);

      if ((offset < 0) || (static_cast<size_t>(offset) >= overwrittenSize)) {
        // Target is to outside of the overwritten area.
        CatValue<uint32>(ppWriter, target - (reinterpret_cast<uint32>(*ppWriter) + sizeof(uint32)));
      }
      else {
        // Target is to inside of the overwritten area, so it needs to point to inside of our copied instructions.
        // Target could be a later instruction we haven't copied yet, so we have to fix this up as a post-process.
        internalRelocs.emplace_back(reinterpret_cast<uint32*>(*ppWriter), static_cast<uint8>(offset));
        CatValue<uint32>(ppWriter, 0x00000000);
      }
    }
  }

  for (const auto& reloc : internalRelocs) {
    *(reloc.first) = PcRelPtr(reloc.first, 4, (pBegin + offsetLut[reloc.second]));
    break;
  }
}

// =====================================================================================================================
static Status CreateTrampoline(
  void*    pAddress,
  void**   ppTrampoline,                          // [out] Pointer to where trampoline code begins.
  uint8*   pOverwrittenSize,                      // [out] Total size in bytes of overwritten instructions.
  size_t*  pTrampolineSize,                       // [out] Size in bytes of trampoline allocation.
  size_t   prologSize                  = 0,       // [in]  Bytes to prepend before the trampoline for custom code.
  uint8    offsetLut[MaxOverwriteSize] = nullptr) // [out] LUT of overwritten instruction offsets to trampoline offsets.
{
  assert((pAddress != nullptr) && (ppTrampoline != nullptr) && (pOverwrittenSize != nullptr));
  assert((prologSize % CodeAlignment) == 0);
  
  const auto insns  = g_disasm.Disassemble(pAddress, sizeof(Jmp32));
  Status     status = (insns.size() != 0) ? g_disasm.GetLastError() : Status::FailDisassemble;

  void*  pTrampoline = nullptr;
  size_t allocSize   = 0;

  uint32 oldCount        = 0;
  uint8  overwrittenSize = 0;

  if (status == Status::Ok) {
    // Calculate how many instructions will actually be overwritten by the Jmp32 and their total size.
    bool foundEnd = false;
    for (uint32 i = 0, count = insns.size(); ((i < count) && (overwrittenSize < sizeof(Jmp32))); ++i) {
      const auto& insn = insns[i];

      // Assume int 3, nop, or unknown instructions are padders.
      if (foundEnd && (insn.bytes[0] != 0xCC) && (insn.bytes[0] != 0x90) && (insn.id != X86_INS_INVALID)) {
        break;
      }

      overwrittenSize += insn.size;

      if (foundEnd == false) {
        ++oldCount;

        if ((insn.bytes[0] == 0xC3) || (insn.bytes[0] == 0xC2) || (insn.bytes[0] == 0xCB) || (insn.bytes[0] == 0xCA)) {
          // Assume a return instruction is the end of a branch or the function.
          foundEnd = true;
        }
      }
    }

    if (overwrittenSize >= sizeof(Jmp32)) {
      *pOverwrittenSize = overwrittenSize;
    }
    else if (overwrittenSize >= sizeof(Jmp8)) {
      status = Status::FailDisassemble;

      // Count how many alignment padding bytes are before the function.  If we have enough space for a jmp32 in there,
      // we can overwrite the start of the function with jmp8 to the jmp32 written in the padders.
      uint8* pReader = static_cast<uint8*>(pAddress);

      // Padder bytes are typically int 3 (0xCC), nop (0x90), or NUL.
      for (int32 i = 1; ((pReader[-i] == 0xCC) || (pReader[-i] == 0x90)); ++i) {
        if (i >= static_cast<int32>(sizeof(Jmp32))) {
          *pOverwrittenSize = overwrittenSize;
          status = Status::Ok;
          break;
        }
      }
    }
    else {
      status = Status::FailDisassemble;
    }
  }

  if (status == Status::Ok) {
    // Allocate memory to store the trampoline.
    allocSize   = Align((prologSize + (MaxInstructionSize * oldCount) + sizeof(Jmp32) + CodeAlignment - 1),
                        CodeAlignment);
    pTrampoline = g_allocator.Alloc(allocSize, CodeAlignment);
    status = (pTrampoline != nullptr) ? Status::Ok : Status::FailMemAlloc;
  }

  if (status == Status::Ok) {
    uint8 localOffsetLut[MaxOverwriteSize];
    if (offsetLut == nullptr) {
      memset(&localOffsetLut[0], 0, sizeof(localOffsetLut));
      offsetLut = localOffsetLut;
    }

    // Our trampoline needs to be able to reissue instructions overwritten by the jump to it.
    uint8* pWriter = (static_cast<uint8*>(pTrampoline) + prologSize);
    CopyInstructions(&pWriter, insns.data(), &oldCount, &overwrittenSize, offsetLut);

    // Complete the trampoline by writing a jmp instruction to the original function.
    CatValue<Jmp32>(&pWriter, { 0xE9, PcRelPtr(pWriter, sizeof(Jmp32), PtrInc(pAddress, *pOverwrittenSize)) });

    // Fill in any left over bytes with int 3 padders.
    const size_t remainingSize = allocSize - PtrDelta(pWriter, pTrampoline);
    if (remainingSize > 0) {
      memset(pWriter, 0xCC, remainingSize);
    }
  }

  if ((status != Status::Ok) && (pTrampoline != nullptr)) {
    g_allocator.Free(pTrampoline);
    pTrampoline = nullptr;
  }

  if (status == Status::Ok) {
    *ppTrampoline    = pTrampoline;
    *pTrampolineSize = allocSize;
  }

  return status;
}

// =====================================================================================================================
Status PatchContext::Hook(
  TargetPtr           pAddress,
  const FunctionPtr&  pfnNewFunction,
  void*               pPfnTrampoline)
{
  if ((status_ == Status::Ok) && ((pAddress == nullptr) || (pfnNewFunction == nullptr))) {
    status_ = Status::FailInvalidPointer;
  }

  pAddress = MaybeFixTargetPtr(pAddress);

  void*        pTrampoline     = nullptr;
  uint8        overwrittenSize = 0;
  size_t       trampolineSize  = 0;
  const size_t thunkSize       = (pfnNewFunction.Functor() != nullptr) ? MaxFunctorThunkSize : 0;

  if (status_ == Status::Ok) {
    // Destroy any existing trampoline or functor.
    Revert(pAddress);
  }

  if (status_ == Status::Ok) {
    if (pPfnTrampoline != nullptr) {
      status_ = CreateTrampoline(pAddress, &pTrampoline, &overwrittenSize, &trampolineSize, thunkSize);

      if ((status_ == Status::Ok) && (thunkSize != 0)) {
        if (CreateFunctorThunk(pfnNewFunction, pTrampoline) == nullptr) {
          status_ = Status::FailInvalidCallback;
        }
      }
    }
    else {
      // ** TODO We should disasemble even in this case to figure out if we need to do a jmp8-to-jmp32-type patch
      overwrittenSize = sizeof(Jmp32);

      if (thunkSize != 0) {
        pTrampoline    = CreateFunctorThunk(pfnNewFunction);
        trampolineSize = thunkSize;
        status_        = (pTrampoline != nullptr) ? Status::Ok : Status::FailInvalidCallback;
      }
    }
  }

  const void*const pHookFunction = (thunkSize == 0) ? pfnNewFunction.Pfn() : pTrampoline;

  if (status_ == Status::Ok) {
    if (overwrittenSize >= sizeof(Jmp32)) {
      // There is enough space to write a jmp32 at pAddress.
#pragma pack(push, 1)
      struct {
        Jmp32 jmpToHookFunction;
        uint8 pad[MaxOverwriteSize - sizeof(Jmp32)];
      } jmp32;
#pragma pack(pop)

      jmp32.jmpToHookFunction = { 0xE9, PcRelPtr(pAddress, sizeof(Jmp32), pHookFunction) };

      if (overwrittenSize > sizeof(Jmp32)) {
        // Write no-ops if an instruction is partially overwritten if we are generating a trampoline.
        memset(&jmp32.pad[0], 0x90, sizeof(jmp32.pad));
      }

      Memcpy(pAddress, &jmp32, overwrittenSize);
    }
    else if (overwrittenSize >= sizeof(Jmp8)) {
      // There isn't enough space for a jmp32 at pAddress, but there is in the padding bytes preceding it.
#pragma pack(push, 1)
      struct {
        Jmp32 jmpToHookFunction;
        Jmp8  jmpToPreviousInsn;
        uint8 pad[MaxOverwriteSize - (sizeof(Jmp32) + sizeof(Jmp8))];
      } indirectJmp32;
#pragma pack(pop)

      indirectJmp32.jmpToHookFunction = { 0xE9, static_cast<uint32>(PtrDelta(pHookFunction, pAddress)) };
      indirectJmp32.jmpToPreviousInsn =
        { 0xEB, PcRelPtr<int8>(&indirectJmp32.jmpToPreviousInsn, sizeof(Jmp8), &indirectJmp32.jmpToHookFunction) };

      if (overwrittenSize > sizeof(Jmp8)) {
        // Write no-ops if an instruction is partially overwritten if we are generating a trampoline.
        memset(&indirectJmp32.pad[0], 0x90, sizeof(indirectJmp32.pad));
      }

      void*const pPatchAddr = PtrDec(pAddress, sizeof(Jmp32));
      Memcpy(pPatchAddr, &indirectJmp32, (overwrittenSize + sizeof(Jmp32)));

      if (status_ == Status::Ok) {
        // Fix up the lookup address key in the historyAt_ map so we can still revert by the user-supplied address.
        auto it = historyAt_.find(pPatchAddr);
        historyAt_[pAddress] = it->second;
        historyAt_.erase(it);
      }
    }
    else {
      // Not enough space to write a jump to our hook function.
      status_ = Status::FailInstallHook;
    }
  }

  if (status_ == Status::Ok) {
    PatchInfo& entry = *historyAt_[pAddress];

    // Add trampoline/functor info to the history tracker entry for this patch so we can clean it up later.
    entry.pTrackedAlloc     = pTrampoline;
    entry.trackedAllocSize  = trampolineSize;
    entry.pFunctorObj       = pfnNewFunction.Functor();
    entry.pfnFunctorDeleter = pfnNewFunction.FunctorDeleter();

    if (pPfnTrampoline != nullptr) {
      *static_cast<void**>(pPfnTrampoline) = PtrInc(pTrampoline, thunkSize);
    }
  }

  if (status_ != Status::Ok) {
    if (pTrampoline != nullptr) {
      g_allocator.Free(pTrampoline);
    }
    pfnNewFunction.Destroy();
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::HookCall(
  TargetPtr           pAddress,
  const FunctionPtr&  pfnNewFunction,
  void*               pPfnOriginal)
{
  if ((status_ == Status::Ok) && ((pAddress == nullptr) || (pfnNewFunction == nullptr))) {
    status_ = Status::FailInvalidPointer;
  }

  pAddress = MaybeFixTargetPtr(pAddress);
  auto*const pInsn = static_cast<uint8*>(pAddress);

  if (status_ == Status::Ok) {
    // Destroy any existing trampoline or functor.
    Revert(pAddress);
  }

  void* pFunctorThunk = nullptr;
  if ((status_ == Status::Ok) && (pfnNewFunction.Functor() != nullptr)) {
    pFunctorThunk = CreateFunctorThunk(pfnNewFunction);
    if (pFunctorThunk == nullptr) {
      status_ = Status::FailInvalidCallback;
    }
  }

  const void*const pHookFunction = (pFunctorThunk == nullptr) ? pfnNewFunction.Pfn() : pFunctorThunk;
  void*            pfnOriginal   = nullptr;

  if (pInsn[0] == 0xE8) {
    // Call pcrel32
    pfnOriginal = PtrInc(pAddress, sizeof(Call32) + reinterpret_cast<ptrdiff_t&>(pInsn[1]));
    Write(pAddress,  Call32{ 0xE8, PcRelPtr(pAddress, sizeof(Call32), pHookFunction) });
  }
  else if (pInsn[0] == 0xFF) {
    size_t insnSize = 0;

    switch (pInsn[1]) {
    // Call m32
    case 0x15:                     pfnOriginal = *reinterpret_cast<void**&>(pInsn[2]);  insnSize = 6;  break;
    // Call r32 (+ r32) (* {2,4,8})
    case 0x10:  case 0x11:  case 0x12:  case 0x13:  case 0x16:  case 0x17:              insnSize = 2;  break;
    case 0x14:                                                                          insnSize = 3;  break;
    // Call r32 (+ r32) (* {2,4,8}) + i8
    case 0x50:  case 0x51:  case 0x52:  case 0x53:  case 0x55:  case 0x56:  case 0x57:  insnSize = 3;  break;
    case 0x54:                                                                          insnSize = 4;  break;
    // Call r32 (+ r32) (* {2,4,8}) + i32
    case 0x90:  case 0x91:  case 0x92:  case 0x93:  case 0x95:  case 0x96:  case 0x97:  insnSize = 6;  break;
    case 0x94:                                                                          insnSize = 7;  break;
    }

    if (insnSize >= sizeof(Call32)) {
#pragma pack(push, 1)
      struct {
        Call32  call;
        uint8   pad[MaxInstructionSize - sizeof(Call32)];
      } code;
#pragma pack(pop)

      code.call = { 0xE8, PcRelPtr(pAddress, sizeof(Call32), pHookFunction) };
      memset(&code.pad[0], 0x90, sizeof(code.pad));
      Memcpy(pAddress, &code, insnSize);
    }
    else {
      // ** TODO Support this case using trampolines.
      status_ = Status::FailInstallHook;
    }
  }
  else {
    status_ = Status::FailInstallHook;
  }

  if ((status_ == Status::Ok) && (pPfnOriginal != nullptr)) {
    // ** TODO Possibly implement this for call r32 variants, for now returns nullptr in those cases
    *static_cast<void**>(pPfnOriginal) = pfnOriginal;
  }

  if ((status_ == Status::Ok) && (pfnNewFunction.Functor() != nullptr)) {
    PatchInfo& entry = *historyAt_[pAddress];

    // Add trampoline info to the history tracker entry for this patch so we can clean it up later.
    entry.pTrackedAlloc     = pFunctorThunk;
    entry.trackedAllocSize  = MaxFunctorThunkSize;
    entry.pFunctorObj       = pfnNewFunction.Functor();
    entry.pfnFunctorDeleter = pfnNewFunction.FunctorDeleter();
  }

  if (status_ != Status::Ok) {
    if (pFunctorThunk != nullptr) {
      g_allocator.Free(pFunctorThunk);
    }
    pfnNewFunction.Destroy();
  }

  return status_;
}

// =====================================================================================================================
// Helper function to generate low-level hook trampoline code.
static size_t CreateLowLevelHookTrampoline(
  void*               pLowLevelHook,
  Span<Register>      registers,
  uint32              byRefMask,
  const void*         pAddress,
  const FunctionPtr&  pfnHookCb,
  ptrdiff_t           moduleRelocDelta,
  const uint8         (&offsetLut)[MaxOverwriteSize],
  uint8               overwrittenSize,
  uint32              options)
{
  using Insn = ConstArray<uint8, 2>;
#if PATCHER_X86_32  //                       Eax:    Ecx:    Edx:    Ebx:    Esi:    Edi:    Ebp:    Esp:    Eflags:
  static constexpr Insn     PushInsns[] = { {0x50}, {0x51}, {0x52}, {0x53}, {0x56}, {0x57}, {0x55}, {0x54}, {0x9C} };
  static constexpr Insn     PopInsns[]  = { {0x58}, {0x59}, {0x5A}, {0x5B}, {0x5E}, {0x5F}, {0x5D}, {0x5C}, {0x9D} };
  static constexpr Register VolatileRegisters[] = { Register::Eflags, Register::Ecx, Register::Edx, Register::Eax };
  static constexpr Register ReturnRegister      = Register::Eax;
  static constexpr Register StackRegister       = Register::Esp;
#elif PATCHER_X86_64
  static constexpr Insn     PushInsns[] = {
  // Rax:    Rcx:    Rdx:    Rbx:    Rsi:    Rdi:    Rbp:    R8:           R9:           R10:          R11:
    {0x50}, {0x51}, {0x52}, {0x53}, {0x56}, {0x57}, {0x55}, {0x41, 0x50}, {0x41, 0x51}, {0x41, 0x52}, {0x41, 0x53},
  // R12:          R13:          R14:          R15:          Rsp:    Rflags:
    {0x41, 0x54}, {0x41, 0x55}, {0x41, 0x56}, {0x41, 0x57}, {0x54}, {0x9C}
  };
  static constexpr Insn     PopInsns[]  = {
    {0x58}, {0x59}, {0x5A}, {0x5B}, {0x5E}, {0x5F}, {0x5D}, {0x41, 0x58}, {0x41, 0x59}, {0x41, 0x5A}, {0x41, 0x5B},
    {0x41, 0x5C}, {0x41, 0x5D}, {0x41, 0x5E}, {0x41, 0x5F}, {0x5C}, {0x9D}
  };
  static constexpr Register VolatileRegisters[] = {
    Register::R8,  Register::R9,  Register::R10, Register::R11, Register::Rflags, Register::Rdi, Register::Rsi,
    Register::Rcx, Register::Rdx, Register::Rax
  };
  static constexpr Register ReturnRegister      = Register::Rax;
  static constexpr Register StackRegister       = Register::Rsp;
#endif
  static constexpr Register ByReference         = Register::Count;  // Placeholder for args by reference.

  // Fix user-provided options to ignore redundant flags.
  if (BitFlagTest(options, LowLevelHookOpt::NoCustomReturnAddr)) {
    options &=
      ~(LowLevelHookOpt::NoBaseRelocReturn | LowLevelHookOpt::NoShortReturnAddr | LowLevelHookOpt::NoNullReturnAdjust);
  }

  // Fix user-provided byRefMask such that UINT_MAX = all registers.
  const uint32 highBit = (1u << (registers.Length() - 1));
  byRefMask = registers.IsEmpty() ? 0 : (byRefMask & (highBit | (highBit - 1u)));

  std::vector<Register> stackRegisters;  // Registers, in order they are pushed to the stack in (RTL).
  stackRegisters.reserve(registers.Length() + ArrayLen(VolatileRegisters) + PopCount(byRefMask));
  uint32 returnRegIndex = UINT_MAX;
  uint32 stackRegIndex  = UINT_MAX;
  uint32 firstArgIndex  = 0;

  auto AddRegisterToStack = [&stackRegisters, &returnRegIndex, &stackRegIndex](Register reg) {
    if ((reg == ReturnRegister) && (returnRegIndex == UINT_MAX)) {
      returnRegIndex = stackRegisters.size();
    }
    else if ((reg == StackRegister) && (stackRegIndex == UINT_MAX)) {
      stackRegIndex = stackRegisters.size();
    }
    stackRegisters.push_back(reg);
  };

  // Registers that are considered volatile between function calls must be pushed to the stack unconditionally.
  // Find which ones haven't been explicitly requested, and have them be pushed to the stack before everything else.
  uint32 requestedRegMask = 0;
  if (registers.IsEmpty() == false) {
    for (uint32 i = 0; i < registers.Length(); ++i) {
      assert(registers[i] < Register::Count);
      requestedRegMask |= (1u << static_cast<uint32>(registers[i]));
    }
  }
  for (const Register reg : VolatileRegisters) {
    if (BitFlagTest(requestedRegMask, 1u << static_cast<uint32>(reg)) == false) {
      AddRegisterToStack(reg);
    }
  }

  if (registers.IsEmpty() == false) {
    // Registers by reference must be pushed prior to function args;  references to them are pushed alongside the args.
    for (uint32 i = 0, mask = byRefMask; BitScanFwdIter(&i, mask); mask &= ~(1u << i)) {
      AddRegisterToStack(registers[i]);
    }

    // Push the function args the user-provided callback will actually see now.
    firstArgIndex = stackRegisters.size();
    for (size_t i = registers.Length(); i > 0; --i) {
      const size_t index = i - 1;
      AddRegisterToStack(BitFlagTest(byRefMask, 1u << index) ? ByReference : registers[index]);
    }

    if (BitFlagTest(options, LowLevelHookOpt::ArgsAsStructPtr)) {
      // Pushing ESP last is equivalent of pushing a pointer to everything before it on the stack.
      AddRegisterToStack(StackRegister);
    }
  }

  // Write the low-level hook trampoline code.
  uint8* pWriter = static_cast<uint8*>(pLowLevelHook);

  auto Push = [&pWriter](Register r)
    { const auto& insn = PushInsns[static_cast<uint32>(r)];  CatBytes(&pWriter, &insn[0], insn.Size()); };
  auto Pop  = [&pWriter](Register r)
    { const auto& insn = PopInsns[static_cast<uint32>(r)];   CatBytes(&pWriter, &insn[0], insn.Size()); };

  Register spareRegister        = Register::Count;
  auto     PushAdjustedStackReg = [&pWriter, &stackRegisters, &spareRegister, &Push](size_t index, size_t offset) {
    if (offset == 0) {
      Push(StackRegister);  // push esp
    }
    else {
      // See if there's an already-stored register we can use.
      if (spareRegister == Register::Count) {
        for (auto it = stackRegisters.begin(); it != (stackRegisters.begin() + index); ++it) {
          const Register reg = *it;
          if (reg < Register::GprLast) {
            spareRegister = reg;
            break;
          }
        }
      }

      if (spareRegister != Register::Count) {
        const uint32 regIdx = static_cast<uint32>(spareRegister);
#if PATCHER_X86_32                            // Eax:  Ecx:  Edx:  Ebx:  Esi:  Edi:
        static constexpr uint8 LeaOperands[] = { 0x44, 0x4C, 0x54, 0x5C, 0x74, 0x7C, };
#elif PATCHER_X86_64
        static constexpr uint8 LeaOperands[] =
        //  Rax:  Rcx:  Rdx:  Rbx:  Rsi:  Rdi:  R8:   R9:   R10:  R11:  R12:  R13:  R14:  R15:
          { 0x44, 0x4C, 0x54, 0x5C, 0x74, 0x7C, 0x44, 0x4C, 0x54, 0x5C, 0x64, 0x6C, 0x74, 0x7C};
        CatByte(&pWriter, (spareRegister < Register::R8) ? 0x48 : 0x4C);
#endif
        CatBytes(&pWriter, { 0x8D, LeaOperands[regIdx], 0x24, static_cast<uint8>(4 * offset) }); // lea  r32, [esp + i8]
        Push(spareRegister);                                                                     // push r32
      }
      else {
        // No spare registers.  Push stack pointer then adjust it on the stack in-place.  May be slower.
        Push(StackRegister);                                                       // push esp
#if PATCHER_X86_64
        CatByte(&pWriter, 0x67);
#endif
        CatBytes(&pWriter, { 0x83, 0x04, 0x24, static_cast<uint8>(4 * offset) });  // add  dword ptr [esp], i8
      }
    }
  };

  // Push required registers to the stack in RTL order, per the cdecl calling convention.
  uint8 numReferencesPushed = 0;
  for (auto it = stackRegisters.begin(); it != stackRegisters.end(); ++it) {
    const Register reg = *it;
    if (reg == StackRegister) {
      PushAdjustedStackReg(stackRegIndex, stackRegIndex);
    }
    else if (reg != ByReference) {
      Push(reg);  // push r32
    }
    else {
      // Register by reference.
      const size_t index  = (it - stackRegisters.begin());
      const size_t offset = (index - firstArgIndex) + (numReferencesPushed++);
      assert(index >= firstArgIndex);
      PushAdjustedStackReg(index, offset);
    }
  }

  auto PopNil = [&pWriter, pLowLevelHook](int8 count = 1) {
#if PATCHER_X86_32
    constexpr uint8 SkipPop[] = { 0x83, 0xC4, 0x00 };        // add esp, 0x0
#elif PATCHER_X86_64
    constexpr uint8 SkipPop[] = { 0x48, 0x83, 0xC4, 0x00 };  // add rsp, 0x0
#endif
    assert(count <= (INT8_MAX / RegisterSize));
    const int8 skipSize = (count * RegisterSize);
    if ((PtrDelta(pWriter, pLowLevelHook) >= sizeof(SkipPop))                                           &&
        (memcmp(&SkipPop[0], &pWriter[-static_cast<int32>(sizeof(SkipPop))], sizeof(SkipPop) - 1) == 0) &&
        ((pWriter[-1] + skipSize) <= INT8_MAX))
    {
      // Combine adjacent skips.
      pWriter[-1] += skipSize;
    }
    else {
      CatValue(&pWriter, SkipPop);
      pWriter[-1] = skipSize;
    }
  };

#if PATCHER_X86_64
  // The x64 calling convention puts the first 4 arguments in registers.
  // ** TODO Moving from register to register would be more optimal, but then we'd have to deal with potential
  //         dependencies (if any arg registers e.g. RCX are requested), and reorder the movs or fall back to
  //         xchg/push+pop as needed.
  static constexpr Register ArgRegisters[] = { Register::Rcx, Register::Rdx, Register::R8, Register::R9 };
  const size_t numArgRegisters = (std::max)(stackRegisters.size(), 4u);
  for (uint32 i = 0; i < numArgRegisters; ++i) {
    Pop(ArgRegisters[i]);
  }
#endif

  uint8*     pSkipCase1Offset = nullptr;
  void*const pTrampolineToOld = PtrInc(pLowLevelHook, MaxLowLevelHookSize);

  // Write the call instruction to our hook callback function.
  // If return value == nullptr, or custom return destinations aren't allowed, we can take a simpler path.
  if (pfnHookCb.Functor() == nullptr) {
    CatValue(&pWriter, Call32{ 0xE8, PcRelPtr(pWriter, sizeof(Call32), pfnHookCb) });   // call pcrel32
  }
  else {
    // ** TODO this needs to be fixed for x64
    CatBytes(&pWriter, { 0x6A, 0x00 });                                                 // push 0x0
    CatValue(&pWriter, Op1_4{ 0x68, reinterpret_cast<uintptr>(pfnHookCb.Functor()) });  // push pFunctor
    CatValue(&pWriter, Call32{ 0xE8, PcRelPtr(pWriter, sizeof(Call32), pfnHookCb) });   // call pcrel32
    PopNil(2);                                                                          // add  esp, 0x8
  }

  if (BitFlagTest(options, LowLevelHookOpt::NoCustomReturnAddr | LowLevelHookOpt::NoNullReturnAdjust) == false) {
#if PATCHER_X86_64
    CatByte(&pWriter, 0x48 );
#endif
    CatBytes(&pWriter, { 0x85, 0xC0,                                                    // test eax, eax
                         0x75, 0x00 });                                                 // jnz  short i8
    pSkipCase1Offset = (pWriter - 1);  // This will be filled later when we know the size.
  }

  if (BitFlagTest(options, LowLevelHookOpt::NoNullReturnAdjust) == false) {
    // Case 1: Return to original destination (hook function returned nullptr, or custom returns are disabled)
    // (Re)store register values from the stack.
    for (auto it = stackRegisters.rbegin(); it != stackRegisters.rend(); ++it) {
      const Register reg = *it;
      if (((stackRegIndex == 0) || (reg != StackRegister)) && (reg != ByReference)) {
        Pop(reg);  // pop r32
      }
      else {
        // Skip this arg.  (If this is the stack register, it will be popped later.)
        PopNil();
      }
    }

    if (BitFlagTest(requestedRegMask, 1u << static_cast<uint32>(StackRegister)) && (stackRegIndex != 0)) {
      // (Re)store ESP.
      const uint8 offset = static_cast<uint8>(-static_cast<int32>(RegisterSize) * (stackRegIndex + 1));
#if PATCHER_X86_32
      CatBytes(&pWriter, { 0x8B, 0x64, 0x24, offset });        // mov esp, dword ptr [esp + i8]
#elif PATCHER_X86_64
      CatBytes(&pWriter, { 0x48, 0x8B, 0x64, 0x24, offset });  // mov rsp, qword ptr [rsp + i8]
#endif
    }

    // Jump to the trampoline to the original function.
    CatValue(&pWriter, Jmp32{ 0xE9, PcRelPtr(pWriter, sizeof(Jmp32), pTrampolineToOld) });  // jmp pcrel32
  }

  if (BitFlagTest(options, LowLevelHookOpt::NoCustomReturnAddr) == false) {
    if (pSkipCase1Offset != nullptr) {
      // Write the skip branch jmp offset now that we know the end of this branch.
      *pSkipCase1Offset = static_cast<uint8>(PtrDelta(pWriter, pSkipCase1Offset) - 1);
    }

    // Case 2: Return to custom destination
    if ((BitFlagTest(options, LowLevelHookOpt::NoBaseRelocReturn) == false) && (moduleRelocDelta != 0)) {
      CatValue(&pWriter, Op1_4{ 0x05, static_cast<uint32>(moduleRelocDelta) });  // add eax, u32
    }

    // If the destination is within the overwritten area, relocate it into the trampoline instead to execute the
    // intended code path.
#pragma pack(push, 1)
    struct RelocateIntoTrampolineCodeChunk {
      // Test if the destination is within the overwritten area.
      Op1_4  testAfterOverwrite  = { 0x3D, };                     // cmp eax, u32
      Jmp8   skipBranch1         = { 0x73, sizeof(branch1) };     // jae short i8

      struct {
        Op1_4  testBeforeOverwrite = { 0x3D, };                   // cmp eax, u32
        Jmp8   skipBranch1A        = { 0x72, sizeof(branch1A) };  // jb short i8

        struct { // Relocate destination into the trampoline to the original function.
          Op1_4  subtractOldAddress  = { 0x2D, };                 // sub eax, u32
          Op2_4  offsetTableLookup   = { { 0x8A, 0x80 }, };       // mov al, [u32 + eax]
          Op1_4  addTrampolineToOld  = { 0x05, };                 // add eax, u32
        } branch1A{};
      } branch1{};
    } static constexpr RelocateIntoTrampolineCodeChunkImage;
#pragma pack(pop)

    auto*const pRelocateCode = reinterpret_cast<RelocateIntoTrampolineCodeChunk*>(pWriter);

    if (BitFlagTest(options, LowLevelHookOpt::NoShortReturnAddr) == false) {
      CatValue(&pWriter, RelocateIntoTrampolineCodeChunkImage);
      pRelocateCode->testAfterOverwrite.operand                  = PtrInc<uint32>(pAddress, overwrittenSize);
      pRelocateCode->branch1.testBeforeOverwrite.operand         = reinterpret_cast<uint32>(pAddress);
      pRelocateCode->branch1.branch1A.subtractOldAddress.operand = reinterpret_cast<uint32>(pAddress);
      // We will defer initializing the offset LUT lookup operand until we know where the LUT will be placed.
      pRelocateCode->branch1.branch1A.addTrampolineToOld.operand = reinterpret_cast<uint32>(pTrampolineToOld);
    }

    // (Re)store register values from the stack.
    for (auto it = stackRegisters.rbegin(); it != stackRegisters.rend(); ++it) {
      const Register reg = *it;
      if (reg == ReturnRegister) {
        // Return register currently holds our return address, so it needs to be special cased.
        if (returnRegIndex != 0) {
          assert(returnRegIndex != UINT_MAX);
          PopNil();
        }
      }
      else if ((reg == ByReference) || (reg == StackRegister)) {
        // Skip arg references; we only care about the actual values they point to further up the stack.
        // Skip stack register.  If it was user-requested, we have a chance to restore it at the end.
        PopNil();
      }
      else {
        Pop(reg);  // pop r32
      }
    }

    if (BitFlagTest(requestedRegMask, 1u << static_cast<uint32>(StackRegister))) {
      // ** TODO Implement overwriting ESP in the custom return destination path.
      // No error or assert here for now for the sake of supporting byRefMask = 0xFFFFFFFF.
    }

    if (returnRegIndex != 0) {
      // Push the return address to the stack, mov the stack variable we skipped earlier to EAX, and return.
      const uint8 offset = static_cast<uint8>(-4 * returnRegIndex);
      Push(ReturnRegister);                            // push eax
      CatBytes(&pWriter, { 0x8B, 0x44, 0x24, offset,   // mov  eax, dword ptr [esp + i8]
                           0xC3 });                    // retn
    }
    else {
      // EAX is the last to pop.  Put the address on the stack just before EAX's value, pop EAX, then jmp to the former.
      CatBytes(&pWriter, { 0x89, 0x44, 0x24, 0xFC });  // mov dword ptr [esp - 4], eax
      Pop(ReturnRegister);                             // pop eax
      CatBytes(&pWriter, { 0xFF, 0x64, 0x24, 0xF8 });  // jmp dword ptr [esp - 8]
    }

    if (BitFlagTest(options, LowLevelHookOpt::NoShortReturnAddr) == false) {
      // Initialize the offset LUT lookup instruction we had deferred, now that we know where we're copying the LUT to.
      pRelocateCode->branch1.branch1A.offsetTableLookup.operand = reinterpret_cast<uint32>(pWriter);
      // Copy the offset lookup table.
      CatBytes(&pWriter, &offsetLut[0], sizeof(offsetLut));
    }
  }

  const size_t size = PtrDelta(pWriter, pLowLevelHook);
  assert(size <= MaxLowLevelHookSize);
  return size;
}

// =====================================================================================================================
Status PatchContext::LowLevelHook(
  TargetPtr           pAddress,
  Span<Register>      registers,
  uint32              byRefMask,
  const FunctionPtr&  pfnHookCb,
  uint32              options)
{
  if ((status_ == Status::Ok) && ((pAddress == nullptr) || (pfnHookCb == nullptr))) {
    status_ = Status::FailInvalidPointer;
  }

  pAddress = MaybeFixTargetPtr(pAddress);

  void*  pTrampoline     = nullptr;
  uint8  overwrittenSize = 0;
  size_t trampolineSize  = 0;
  uint8  offsetLut[MaxOverwriteSize] = { };

  const Call con = pfnHookCb.Signature().convention;
  if ((status_ == Status::Ok) && (con != Call::Cdecl) && (con != Call::Default) && (con != Call::Unknown)) {
    status_ = Status::FailInvalidCallback;
  }

  if (status_ == Status::Ok) {
    // Destroy any existing trampoline or functor.
    Revert(pAddress);
  }

  if (status_ == Status::Ok) {
    status_ = CreateTrampoline(
      pAddress, &pTrampoline, &overwrittenSize, &trampolineSize, MaxLowLevelHookSize, offsetLut);
  }

  if (status_ == Status::Ok) {
    if ((pTrampoline != nullptr) && (overwrittenSize >= sizeof(Jmp32))) {
      // Initialize low-level hook code.
      const size_t usedSize = CreateLowLevelHookTrampoline(pTrampoline,
                                                           registers,
                                                           byRefMask,
                                                           pAddress,
                                                           pfnHookCb,
                                                           moduleRelocDelta_,
                                                           offsetLut,
                                                           overwrittenSize,
                                                           options);

      // Fill in unused bytes with int 3 padders.
      if (MaxLowLevelHookSize > usedSize) {
        memset(PtrInc(pTrampoline, usedSize), 0xCC, (MaxLowLevelHookSize - usedSize));
      }

#pragma pack(push, 1)
      struct {
        Jmp32 instruction;
        uint8 pad[MaxOverwriteSize - sizeof(Jmp32)];
      } jmp;
#pragma pack(pop)

      // Overwrite the original function with a jmp to the low-level hook trampoline.
      jmp.instruction = { 0xE9, PcRelPtr(pAddress, sizeof(Jmp32), pTrampoline) };
      if (overwrittenSize > sizeof(Jmp32)) {
        // Write no-ops if an instruction is partially overwritten.
        memset(&jmp.pad[0], 0x90, sizeof(jmp.pad));
      }

      Memcpy(pAddress, &jmp, overwrittenSize);
    }
    else {
      status_ = Status::FailInstallHook;
    }
  }

  if (status_ == Status::Ok) {
    PatchInfo& entry = *historyAt_[pAddress];

    // Add trampoline (and functor) info to the history tracker entry for this patch so we can clean it up later.
    entry.pTrackedAlloc     = pTrampoline;
    entry.trackedAllocSize  = trampolineSize;
    entry.pFunctorObj       = pfnHookCb.Functor();
    entry.pfnFunctorDeleter = pfnHookCb.FunctorDeleter();
  }

  if (status_ != Status::Ok) {
    if (pTrampoline != nullptr) {
      g_allocator.Free(pTrampoline);
    }
    pfnHookCb.Destroy();
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::EditExports(
  Span<ExportInfo>  exportInfos)
{
  IMAGE_DATA_DIRECTORY*const pExportDataDir = GetDataDirectory(hModule_, IMAGE_DIRECTORY_ENTRY_EXPORT);

  if ((status_ == Status::Ok) && (pExportDataDir == nullptr)) {
    // Not a valid PE image.
    status_ = Status::FailInvalidModule;
  }

  if (status_ == Status::Ok) {
    std::vector<void*>            exports;
    std::unordered_set<uint32>    forwardExportOrdinals;
    std::map<std::string, uint32> namesToOrdinals;  // Name table must be sorted, so use map rather than unordered_map.

    IMAGE_EXPORT_DIRECTORY* pOldExportTable = nullptr;
    char moduleName[512] = "";

    if ((pExportDataDir->VirtualAddress == 0) || (pExportDataDir->Size == 0)) {
      // Module has no export table.
      GetModuleFileNameA(static_cast<HMODULE>(hModule_), &moduleName[0], sizeof(moduleName));
      exports.reserve(exportInfos.Length());
    }
    else {
      // Module has an export table.
      pOldExportTable = static_cast<IMAGE_EXPORT_DIRECTORY*>(PtrInc(hModule_, pExportDataDir->VirtualAddress));
      strncpy_s(
        &moduleName[0], sizeof(moduleName), static_cast<char*>(PtrInc(hModule_, pOldExportTable->Name)), _TRUNCATE);

      auto*const pFunctions    = PtrInc<uint32*>(hModule_, pOldExportTable->AddressOfFunctions);
      auto*const pNames        = PtrInc<uint32*>(hModule_, pOldExportTable->AddressOfNames);
      auto*const pNameOrdinals = PtrInc<uint16*>(hModule_, pOldExportTable->AddressOfNameOrdinals);

      // Copy the module's exports.
      exports.reserve(pOldExportTable->NumberOfFunctions + exportInfos.Length());
      for (uint32 i = 0; i < pOldExportTable->NumberOfNames; ++i) {
        namesToOrdinals.emplace_hint(namesToOrdinals.end(),
                                     std::piecewise_construct,
                                     std::forward_as_tuple(static_cast<const char*>(PtrInc(hModule_, pNames[i]))),
                                     std::forward_as_tuple(pNameOrdinals[i]));
      }
      for (uint32 i = 0; i < pOldExportTable->NumberOfFunctions; ++i) {
        void*const pExportAddress = PtrInc(hModule_, pFunctions[i]);
        if ((pExportAddress >= pOldExportTable) && (pExportAddress < PtrInc(pOldExportTable, pExportDataDir->Size))) {
          forwardExportOrdinals.insert(exports.size());
        }
        exports.emplace_back(pExportAddress);
      }
    }

    // Overlay our exports we want to inject.
    for (uint32 i = 0, nextIndex = exports.size(); ((status_ == Status::Ok) && (i < exportInfos.Length())); ++i) {
      while ((exports.size() > nextIndex) && (exports[nextIndex] != nullptr)) {
        // Fix up next export ordinal, in the case of having added an export by ordinal.
        ++nextIndex;
      }

      auto curExport = exportInfos[i];

      switch (curExport.type) {
      case ExportInfo::ByNameFix:
        curExport.pAddress = FixPtr(curExport.address);
      case ExportInfo::ByName:
        if (curExport.pSymbolName == nullptr) {
          status_ = Status::FailInvalidPointer;
        }
        else if (curExport.pAddress != nullptr) {
          exports.emplace_back(curExport.pAddress);
          namesToOrdinals[curExport.pSymbolName] = nextIndex++;
        }
        else {
          namesToOrdinals.erase(curExport.pSymbolName);
        }
        break;

      case ExportInfo::ByOrdinalFix:
        curExport.pAddress = FixPtr(curExport.address);
      case ExportInfo::ByOrdinal:
        forwardExportOrdinals.erase(curExport.ordinal);
        if (exports.size() < (curExport.ordinal + 1u)) {
          exports.resize(curExport.ordinal + 1u, nullptr);
        }
        exports[curExport.ordinal] = curExport.pAddress;
        if ((curExport.pAddress == nullptr) && (curExport.ordinal == nextIndex)) {
          ++nextIndex;
        }
        break;

      case ExportInfo::Forwarded:
        if ((curExport.pSymbolName == nullptr) || (curExport.pForwardName == nullptr)) {
          status_ = Status::FailInvalidPointer;
        }
        forwardExportOrdinals.insert(nextIndex);
        namesToOrdinals[curExport.pSymbolName] = nextIndex++;
        break;
      }
    }

    // Calculate the amount of space we need to allocate.
    static constexpr uint32 HeaderSize = sizeof(IMAGE_EXPORT_DIRECTORY);
    const uint32 addressTableSize      = sizeof(void*)  * exports.size();
    const uint32 namePtrTableSize      = sizeof(void*)  * namesToOrdinals.size();
    const uint32 nameOrdinalTableSize  = sizeof(uint16) * namesToOrdinals.size();

    uint32 totalNameStrlen = (strlen(moduleName) + 1);
    for (const auto& name : namesToOrdinals) {
      totalNameStrlen += (name.first.length() + 1);
    }

    uint32 totalForwardStrlen = 0;
    for (const auto& ordinal : forwardExportOrdinals) {
      totalForwardStrlen += (strlen(static_cast<const char*>(exports[ordinal])) + 1);
    }

    const uint32 allocSize =
      (HeaderSize + addressTableSize + namePtrTableSize + nameOrdinalTableSize + totalNameStrlen + totalForwardStrlen);
    void*const pAllocation = g_allocator.Alloc(allocSize);

    if (pAllocation != nullptr) {
      auto*const  pHeader              = static_cast<IMAGE_EXPORT_DIRECTORY*>(pAllocation);
      auto*const  pAddressTable        = PtrInc<uint32*>(pAllocation,     HeaderSize);        // By RVA
      auto*       pNameTable           = PtrInc<uint32*>(pAddressTable,   addressTableSize);  // By RVA
      auto*       pNameOrdinalTable    = PtrInc<uint16*>(pNameTable,      namePtrTableSize);
      auto*       pStringBuffer        = PtrInc<char*>(pNameOrdinalTable, nameOrdinalTableSize);
      auto*       pForwardStringBuffer = PtrInc<char*>(pStringBuffer,     totalNameStrlen);

      // Initialize the Export Directory Table header.
      pHeader->Characteristics       = (pOldExportTable != nullptr) ? pOldExportTable->Characteristics : 0;
      pHeader->TimeDateStamp         = (pOldExportTable != nullptr) ? pOldExportTable->TimeDateStamp   : 0;
      pHeader->MajorVersion          = (pOldExportTable != nullptr) ? pOldExportTable->MajorVersion    : 0;
      pHeader->MinorVersion          = (pOldExportTable != nullptr) ? pOldExportTable->MinorVersion    : 0;
      pHeader->Name                  = static_cast<DWORD>(PtrDelta(pStringBuffer,     hModule_));  // By RVA
      pHeader->Base                  = (pOldExportTable != nullptr) ? pOldExportTable->Base            : 1;
      pHeader->NumberOfFunctions     = exports.size();
      pHeader->NumberOfNames         = namesToOrdinals.size();
      pHeader->AddressOfFunctions    = static_cast<DWORD>(PtrDelta(pAddressTable,     hModule_));  // By RVA
      pHeader->AddressOfNames        = static_cast<DWORD>(PtrDelta(pNameTable,        hModule_));  // By RVA
      pHeader->AddressOfNameOrdinals = static_cast<DWORD>(PtrDelta(pNameOrdinalTable, hModule_));  // By RVA

      // Set up the rest of the new export table: Export Address Table, Export Name Pointer Table, Export Ordinal Table,
      // Export Name Table.
      AppendString(&pStringBuffer, moduleName);

      for (uint32 i = 0; i < exports.size(); ++i) {
        if (forwardExportOrdinals.count(i) == 0) {
          pAddressTable[i] = (exports[i] != nullptr) ? static_cast<uint32>(PtrDelta(exports[i], hModule_)) : 0;
        }
        else {
          pAddressTable[i] = static_cast<uint32>(PtrDelta(pForwardStringBuffer, hModule_));
          AppendString(&pForwardStringBuffer, static_cast<const char*>(exports[i]));
        }
      }

      for (const auto& nameOrdinal : namesToOrdinals) {
        *(pNameTable++)        = static_cast<uint32>(PtrDelta(pStringBuffer, hModule_));
        *(pNameOrdinalTable++) = nameOrdinal.second;
        AppendString(&pStringBuffer, nameOrdinal.first);
      }

      // If we previously had injected exports, revert it to clean up the heap allocation for it.
      Revert(pExportDataDir);

      // Modify the module's header to point to our new export table.
      Write(pExportDataDir, IMAGE_DATA_DIRECTORY{ static_cast<DWORD>(PtrDelta(pAllocation, hModule_)), allocSize });

      if (status_ == Status::Ok) {
        // Add export table allocation info to the history tracker entry for this patch so we can clean it up later.
        auto& entry = *historyAt_[pExportDataDir];
        entry.pTrackedAlloc    = pAllocation;
        entry.trackedAllocSize = allocSize;
      }
    }
    else {
      status_ = Status::FailMemAlloc;
    }
  }

  return status_;
}

} // Patcher
