/*
 ***********************************************************************************************************************
 * Copyright (c) 2019, Brad Dorney
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

#if !defined(WIN32_LEAN_AND_MEAN)
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <utility>
#include <limits>
#include <mutex>

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


// x86 fetches instructions on 16-byte boundaries.  Allocated code should be aligned on these boundaries in memory.
static constexpr uint32 CodeAlignment      = 16;
// Max instruction size on modern x86 is 15 bytes.
static constexpr uint32 MaxInstructionSize = 15;
// Worst-case scenario is the last byte overwritten being the start of a MaxInstructionSize-sized instruction.
static constexpr uint32 MaxOverwriteSize   = (sizeof(Jmp32) + MaxInstructionSize - 1);

// Max size in bytes low-level hook trampoline code is expected to require.
static constexpr uint32 MaxLowLevelHookSize = Align(160, CodeAlignment);

static constexpr uint32 OpenThreadFlags =
  (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION);

static constexpr uint32 ExecutableProtectFlags =
  (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
static constexpr uint32 ReadOnlyProtectFlags   = (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE);


// Returns true if any flags are set in mask.
template <typename T1, typename T2>
static constexpr bool BitFlagTest(T1 mask, T2 flags) { return ((mask & flags) != 0); }

// Calculates a hash using std::hash.
template <typename T>
static size_t Hash(const T& src) { return std::hash<T>()(src); }

// Helper functions to append data while incrementing a runner pointer.
static void CatBytes(uint8** ppWriter, std::initializer_list<uint8> src)
  { std::copy(src.begin(), src.end(), *ppWriter);  *ppWriter += src.size(); }
static void CatBytes(uint8** ppWriter, const uint8* pSrc, uint32 count)
  { memcpy(*ppWriter, pSrc, count);  *ppWriter += count; }

template <typename T>
static void CatValue(uint8** ppWriter, const T& value) { memcpy(*ppWriter, &value, sizeof(T)); *ppWriter += sizeof(T); }

static void AppendString(char** ppWriter, const char*       pSrc)
  { const size_t length = (strlen(pSrc) + 1);  strcpy_s(*ppWriter, length, pSrc);        *ppWriter += length; }
static void AppendString(char** ppWriter, const std::string& src)
  { const size_t length = (src.length() + 1);  strcpy_s(*ppWriter, length, src.data());  *ppWriter += length; }

// Gets the length of an array.
template <typename T, size_t N>
static constexpr uint32 ArrayLen(const T (&src)[N]) { return static_cast<uint32>(N); }

// Relocates a TargetPtr if needed.
static void* MaybeRelocateTargetPtr(const PatchContext* pThis, const TargetPtr& ptr)
  { return ptr.ShouldRelocate() ? pThis->FixPtr(ptr) : static_cast<void*>(ptr); }

// Finds the index of the first set bit in a bitmask.  Result is undefined if mask == 0.
#if PATCHER_MSVC && PATCHER_X86
static uint32 BitScanFwd(uint32 mask) { return _tzcnt_u32(mask); }
#elif PATCHER_MSVC
static uint32 BitScanFwd(uint32 mask) { unsigned long index;  _BitScanForward(&index, mask);  return index; }
#elif defined(__GNUC__)
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

// We need to allocate memory such that it can be executed, which requires an extra private heap created with the
// HEAP_CREATE_ENABLE_EXECUTE flag.
class Allocator {
public:
  void Acquire() {
    std::lock_guard<std::mutex> lock(allocatorLock_);
    ++refCount_;
    if (hHeap_ == nullptr) {
      hHeap_ = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    }
  }

  void Release() {
    std::lock_guard<std::mutex> lock(allocatorLock_);
    --refCount_;
    if ((refCount_ == 0) && (hHeap_ != nullptr)) {
      HeapDestroy(hHeap_);
      hHeap_ = nullptr;
    }
  }

  void* Alloc(size_t size)  { return ((hHeap_ != nullptr) ? HeapAlloc(hHeap_, 0, size) : nullptr);    }
  bool  Free(void* pMemory) { return ((hHeap_ != nullptr) && (HeapFree(hHeap_, 0, pMemory) == TRUE)); }

private:
  HANDLE  hHeap_;
  uint32  refCount_;

  std::mutex  allocatorLock_;
};

static Allocator  g_allocator;
static std::mutex g_codeThreadLock;

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
// Translates a Capstone error code to a Patcher Status.
static Status TranslateCsError(
  cs_err  capstoneError)
{
  switch (capstoneError) {
  case CS_ERR_OK:  return Status::Ok;
  default:         return Status::FailDisassemble;
  }
}

// =====================================================================================================================
// Helper function to get the base load address of the module containing pAddress.
// Note that heap memory does not belong to a module, in which case this function returns NULL.
static HMODULE GetModuleFromAddress(
  const void*  pAddress)
{
  static constexpr DWORD Flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
  HMODULE hModule = NULL;
  return (GetModuleHandleExA(Flags, static_cast<LPCSTR>(pAddress), &hModule) == TRUE) ? hModule : NULL;
}

// =====================================================================================================================
static uint32 CalculateModuleHash(
  void*  hModule)
{
  size_t result = 0;
  const auto*const pDosHeader = static_cast<const IMAGE_DOS_HEADER*>(hModule);

  if ((pDosHeader != nullptr) && (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)) {
    const auto&  ntHeader = *static_cast<const IMAGE_NT_HEADERS*>(
      PtrInc(hModule, static_cast<const IMAGE_DOS_HEADER*>(hModule)->e_lfanew));
    const auto&  optionalHeader   = ntHeader.OptionalHeader;
    const auto&  optionalHeader64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64&>(optionalHeader);

    const bool isPe32 = (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    const bool isPe64 = (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    if (isPe32 || isPe64) {
      // Hashing 3 bits of data should be good enough: timestamp, preferred address, and size of code.
      // Optional header contains a checksum field, but it's only ever filled in for signed binaries (e.g. drivers).
      result = Hash(ntHeader.FileHeader.TimeDateStamp);
      result = isPe64 ? Hash(optionalHeader64.ImageBase)  : Hash(optionalHeader.ImageBase);
      result = isPe64 ? Hash(optionalHeader64.SizeOfCode) : Hash(optionalHeader.SizeOfCode);
    }
  }

  return (sizeof(size_t) <= sizeof(uint32)) ?
         static_cast<uint32>(result) : static_cast<uint32>((static_cast<uint64>(result) >> 32) ^ (result & 0xFFFFFFFF));
}

// =====================================================================================================================
static IMAGE_DATA_DIRECTORY* GetDataDirectory(
  void*  hModule,
  uint32 index)
{
  IMAGE_DATA_DIRECTORY* pDataDir = nullptr;
  const auto*const pDosHeader    = static_cast<const IMAGE_DOS_HEADER*>(hModule);

  if ((pDosHeader != nullptr) && (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)) {
    auto& optionalHeader =
      static_cast<IMAGE_NT_HEADERS*>(
        PtrInc(hModule, static_cast<IMAGE_DOS_HEADER*>(hModule)->e_lfanew))->OptionalHeader;
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
  hasModuleRef_(loadModule && (pModuleName != nullptr) && (GetModuleHandleA(pModuleName) == nullptr)),
  hModule_(hasModuleRef_ ? LoadLibraryA(pModuleName) : GetModuleHandleA(pModuleName)),
  moduleRelocDelta_(0),
  moduleHash_(CalculateModuleHash(hModule_)),
  status_(Status::FailInvalidModule)
{
  Init();
}

// =====================================================================================================================
PatchContext::PatchContext(
  void*  hModule)
  :
  hasModuleRef_(false),
  hModule_(hModule),
  moduleRelocDelta_(0),
  moduleHash_(CalculateModuleHash(hModule_)),
  status_(Status::FailInvalidModule)
{
  Init();
}

// =====================================================================================================================
PatchContext::~PatchContext() {
  RevertAll();
  g_allocator.Release();
  ReleaseModule();
}

// =====================================================================================================================
void PatchContext::Init() {
  g_allocator.Acquire();

  const auto*const pDosHeader = static_cast<const IMAGE_DOS_HEADER*>(hModule_);
  if ((pDosHeader != nullptr) && (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)) {
    // Calculate the module's base relocation delta.
    const auto& peHeader = *static_cast<const IMAGE_NT_HEADERS*>(PtrInc(hModule_, pDosHeader->e_lfanew));
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
Status PatchContext::Memcpy(
  TargetPtr    pAddress,
  const void*  pSrc,
  size_t       size)
{
  assert((pAddress != nullptr) && (pSrc != nullptr) && (size != 0));
  void*const pDst = MaybeRelocateTargetPtr(this, pAddress);
  const uint32 oldAttr = BeginDeProtect(pDst, size);

  if (status_ == Status::Ok) {
    memcpy(pDst, pSrc, size);
    EndDeProtect(pDst, size, oldAttr);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::Memset(
  TargetPtr  pAddress,
  uint8      value,
  size_t     count)
{
  assert((pAddress != nullptr) && (count != 0));
  void*const pDst = MaybeRelocateTargetPtr(this, pAddress);

  const uint32 oldAttr = BeginDeProtect(pDst, count);

  if (status_ == Status::Ok) {
    memset(pDst, value, count);
    EndDeProtect(pDst, count, oldAttr);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::Revert(
  TargetPtr  pAddress)
{
  Status tmpStatus = Status::Ok;
  std::swap(tmpStatus, status_);

  const auto it = historyAt_.find(pAddress.ShouldRelocate() ? FixPtr(pAddress) : static_cast<void*>(pAddress));

  if (it != historyAt_.end()) {
    const auto& pDst        = std::get<0>(*it->second);
    const auto& oldBytes    = std::get<1>(*it->second);
    const auto& pAllocation = std::get<2>(*it->second);
    const auto& allocSize   = std::get<3>(*it->second);

    Memcpy(pDst, oldBytes.Data(), oldBytes.Size());

    if (status_ == Status::Ok) {
      if (pAllocation != nullptr) {
        AdvanceThreads(pAllocation, allocSize);

        // If Memcpy failed, this won't get cleaned up until the allocation heap is destroyed.
        g_allocator.Free(pAllocation);
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
    const auto& pAddress    = std::get<0>(entry);
    const auto& oldBytes    = std::get<1>(entry);
    const auto& pAllocation = std::get<2>(entry);
    const auto& allocSize   = std::get<3>(entry);

    Memcpy(pAddress, oldBytes.Data(), oldBytes.Size());

    if (((status_ == Status::Ok) || (status_ == Status::FailModuleUnloaded)) && (pAllocation != nullptr)) {
      AdvanceThreads(pAllocation, allocSize);

      // If Memcpy failed, this won't get cleaned up until the trampoline allocation heap is destroyed.
      g_allocator.Free(pAllocation);
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
static constexpr uintptr_t GetProgramCounter(
  const CONTEXT& context)
{
#if PATCHER_X86_32
  return static_cast<uintptr_t>(context.Eip);
#elif PATCHER_X86_64
  return static_cast<uintptr_t>(context.Rip);
#else
  assert(false);
  return 0;
#endif
}

// =====================================================================================================================
Status PatchContext::LockThreads() {
  g_codeThreadLock.lock();

#if (PATCHER_X86 == false)
  status_ = Status::FailUnsupported;
#endif

  // Create a snapshot of current process threads.
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

  if (hSnapshot != INVALID_HANDLE_VALUE) {
    const auto thisProcessId = GetCurrentProcessId();
    const auto thisThreadId  = GetCurrentThreadId();

    THREADENTRY32 entry = { };
    entry.dwSize = sizeof(entry);

    for (auto x = Thread32First(hSnapshot, &entry); (status_ == Status::Ok) && x; x = Thread32Next(hSnapshot, &entry)) {
      if ((entry.dwSize             >  offsetof(THREADENTRY32, th32OwnerProcessID)) &&
          (entry.th32OwnerProcessID == thisProcessId) &&
          (entry.th32ThreadID       != thisThreadId))
      {
        HANDLE hThread = OpenThread(OpenThreadFlags, FALSE, entry.th32ThreadID);
        if (hThread != nullptr) {
          SuspendThread(hThread);

          CONTEXT ctx;
          ctx.ContextFlags = CONTEXT_CONTROL;
          uintptr_t pc = 0;

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
    if (hThread != nullptr) {
      ResumeThread(hThread);
      CloseHandle(hThread);
    }
  }

  frozenThreads_.clear();
  g_codeThreadLock.unlock();
  return status_;
}

// =====================================================================================================================
static uintptr_t AdvanceThread(
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
  const uintptr_t address = reinterpret_cast<uintptr_t>(pAddress);

  for (auto& threadInfo : frozenThreads_) {
    if ((threadInfo.second >= address) && (threadInfo.second < (address + size))) {
      HANDLE hThread = OpenThread(OpenThreadFlags, FALSE, threadInfo.first);

      if (hThread != nullptr) {
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
  void*const pDst = MaybeRelocateTargetPtr(this, pAddress);

  if (status_ == Status::Ok) {
    // Make a copy of the original data if it hasn't been tracked already so we can revert it later.
    auto it = historyAt_.find(pDst);
    if (it == historyAt_.end()) {
      const size_t oldSize = history_.size();
      history_.emplace_front(pDst, ByteArray<StorageSize>(pDst, size), nullptr, 0);

      if ((history_.size() == oldSize) || (historyAt_.emplace(pDst, history_.begin()).first == historyAt_.end())) {
        status_ = Status::FailMemAlloc;
      }
    }
    else {
      auto& trackedOldBytes = std::get<1>(*it->second);
      if (trackedOldBytes.Size() < size) {
        // Merge the original tracked data with the extra bytes we also need to track.
        trackedOldBytes.Append(PtrInc(pDst, trackedOldBytes.Size()), (size - trackedOldBytes.Size()));
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

  if (status_ == Status::Ok) {
    const HMODULE hModule = GetModuleFromAddress(pAddress);
    // Note:  Heap-allocated memory isn't associated with any module, in which case hModule will be set to nullptr.
    if ((hModule != nullptr) && (CalculateModuleHash(hModule) != moduleHash_)) {
      status_ = Status::FailModuleUnloaded;
    }
  }

  if (status_ == Status::Ok) {
    // Query memory page protection information to determine how we need to barrier around making this memory writable.
    MEMORY_BASIC_INFORMATION memInfo;

    if ((VirtualQuery(pAddress, &memInfo, sizeof(memInfo)) >= offsetof(MEMORY_BASIC_INFORMATION, Protect)) &&
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
#pragma pack(push, 1)
  struct RelocInfo {
    uint16 offset : 12; // Offset, relative to VirtualAddress of the parent block
    uint16 type   : 4;  // IMAGE_REL_BASED_x - HIGHLOW (x86_32) or DIR64 (x86_64)
  };
#pragma pack(pop)

  assert((pOldGlobal != nullptr) && (pNewGlobal != nullptr));
  void*const pOld = MaybeRelocateTargetPtr(this, pOldGlobal);

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
    const auto*const pRelocTable = static_cast<IMAGE_BASE_RELOCATION*>(PtrInc(hModule_, pRelocDataDir->VirtualAddress));
    const auto*      pCurBlock   = pRelocTable;

    // Iterate through relocation table blocks.  Each block typically represents 4096 bytes, e.g. 0x401000-0x402000.
    while ((status_ == Status::Ok) &&
           (static_cast<const void*>(pCurBlock) < PtrInc(pRelocTable, pRelocDataDir->Size)) &&
           (pCurBlock->SizeOfBlock != 0))
    {
      const auto*const pRelocArray = static_cast<const RelocInfo*>(PtrInc(pCurBlock, sizeof(IMAGE_BASE_RELOCATION)));
      const size_t     numRelocs   = ((pCurBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RelocInfo));

      // Iterate over relocations, find references to the global and replace them.
      for (size_t i = 0; ((status_ == Status::Ok) && (i < numRelocs)); ++i) {
        void*const   ppAddress = (static_cast<uint8*>(hModule_) + pCurBlock->VirtualAddress + pRelocArray[i].offset);
        const void*  pAddress  = nullptr;
        size_t       ptrSize   = 0;

        if (pRelocArray[i].type == IMAGE_REL_BASED_HIGHLOW) {
          pAddress = reinterpret_cast<const void*>(*static_cast<uint32*>(ppAddress));
          ptrSize = 4;
        }
        else if (pRelocArray[i].type == IMAGE_REL_BASED_DIR64) {
          pAddress = reinterpret_cast<const void*>(*static_cast<uint64*>(ppAddress));
          ptrSize = 8;
        }

        if ((pAddress != nullptr) && (ptrSize != 0)) {
          const size_t delta = PtrDelta(pAddress, pOld);

          if ((pAddress >= pOld) && (delta < size)) {
            // Found a reference to the global we want to replace.  Patch it.
            const uint64 newAddress = (reinterpret_cast<uintptr_t>(pNewGlobal) + delta);
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
      pCurBlock = static_cast<const IMAGE_BASE_RELOCATION*>(PtrInc(pCurBlock, pCurBlock->SizeOfBlock));
    }
  }

  if (status_ != Status::Ok) {
    for (auto it = (pRefsOut->begin() + startIndex); it != pRefsOut->end(); ++it) {
      Revert(*it);
    }
    pRefsOut->erase((pRefsOut->begin() + startIndex), pRefsOut->end());
  }

  return status_;
}

// =====================================================================================================================
static void CopyInstructions(
  uint8**   ppWriter,
  cs_insn*  pInsns,
  size_t*   pCount,
  uint8*    pOverwrittenSize,
  uint8     offsetLut[MaxOverwriteSize])
{
  assert(
    (ppWriter != nullptr) && (pInsns != nullptr) && (pCount != nullptr) && (*pCount != 0) && (offsetLut != nullptr));

  uint8*const  pBegin     = *ppWriter;
  size_t  curOldOffset    = 0;
  size_t  count           = *pCount;
  uint8   overwrittenSize = *pOverwrittenSize;
  bool    foundEnd        = false;
  std::vector<std::pair<uint32*, uint8>> deferredRelocs;

  for (size_t i = 0; ((foundEnd == false) && (i < count)); ++i) {
    uintptr_t pcRelTarget = 0;

    // Store mapping of the original instruction to the offset of the new instruction we're writing.
    offsetLut[curOldOffset] = static_cast<uint8>(PtrDelta(*ppWriter, pBegin));
    curOldOffset += pInsns[i].size;

    // Instructions which use PC relative operands need to be changed to their 32-bit forms and fixed up.
    switch (pInsns[i].id) {
    case X86_INS_CALL:
      if (pInsns[i].bytes[0] == 0xE8) {
        CatValue<uint8>(ppWriter, 0xE8);
        const auto*const pCall = reinterpret_cast<const Call32*>(&pInsns[i].bytes[0]);
        pcRelTarget = pCall->operand;
      }
      break;

    case X86_INS_JMP:
      if (pInsns[i].bytes[0] == 0xE9) {
        CatValue<uint8>(ppWriter, 0xE9);
        const auto*const pJmp = reinterpret_cast<const Jmp32*>(&pInsns[i].bytes[0]);
        pcRelTarget = pJmp->operand;
      }
      else if (pInsns[i].bytes[0] == 0xEB) {
        CatValue<uint8>(ppWriter, 0xE9);
        pcRelTarget = pInsns[i].bytes[1];
      }
      break;

    // Jump if condition
    case X86_INS_JAE:  case X86_INS_JA:   case X86_INS_JBE:  case X86_INS_JB:   case X86_INS_JE:   case X86_INS_JGE:
    case X86_INS_JG:   case X86_INS_JLE:  case X86_INS_JL:   case X86_INS_JNE:  case X86_INS_JNO:  case X86_INS_JNP:
    case X86_INS_JNS:  case X86_INS_JO:   case X86_INS_JP:   case X86_INS_JS:
      if ((pInsns[i].bytes[0] == 0x0F) && (pInsns[i].bytes[1] >= 0x80) && (pInsns[i].bytes[1] <= 0x8F)) {
        CatBytes(ppWriter, { 0x0F, pInsns[i].bytes[1] });
        const auto*const pJmp = reinterpret_cast<const Op2_4*>(&pInsns[i].bytes[0]);
        pcRelTarget = pJmp->operand;
      }
      else if ((pInsns[i].bytes[0] >= 0x70) && (pInsns[i].bytes[0] <= 0x7F)) {
        CatBytes(ppWriter, { 0x0F, static_cast<uint8>(pInsns[i].bytes[0] + 0x10) });
        pcRelTarget = pInsns[i].bytes[1];
      }
      else if (pInsns[i].bytes[0] == 0xEB) {
        // Workaround for Capstone issue where jmp short sometimes identifies as conditional jump.
        CatValue<uint8>(ppWriter, 0xE9);
        pcRelTarget = pInsns[i].bytes[1];
      }
      break;

    // Loop, jump if ECX == 0
    case X86_INS_LOOP:  case X86_INS_LOOPE:  case X86_INS_LOOPNE:  case X86_INS_JCXZ:  case X86_INS_JECXZ:
      if (pInsns[i].bytes[0] >= 0xE0 && pInsns[i].bytes[0] <= 0xE3) {
        // LOOP* and JECX have no 32-bit operand versions, so we have to use multiple jump instructions to emulate it.
        CatValue<uint8>(ppWriter, pInsns[i].bytes[0]);

        struct {
          uint8  operand     = sizeof(skipTarget);       // (byte)
          Jmp8   skipTarget  = { 0xEB, sizeof(Jmp32) };  // jmp short (sizeof(Jmp32))
          uint8  jmp32Opcode = 0xE9;                     // jmp near (dword)
        } static constexpr CodeChunk;
        static_assert((sizeof(uint8) + sizeof(CodeChunk) + sizeof(uint32)) <= MaxInstructionSize,
                      "Set of instructions for LOOP/JECX near emulation is too large.");

        CatValue(ppWriter, CodeChunk);
        pcRelTarget = pInsns[i].bytes[1];
      }
      break;

    default:
      break;
    }

    if (pcRelTarget == 0) {
      // Just copy instructions without PC rel operands verbatim.
      CatBytes(ppWriter, &pInsns[i].bytes[0], pInsns[i].size);
    }
    else {
      // Instructions with PC rel operands must be fixed up.
      const uintptr_t target = static_cast<uintptr_t>(pcRelTarget + pInsns[i].address + pInsns[i].size);
      const ptrdiff_t offset = static_cast<ptrdiff_t>(target - pInsns[0].address);

      if ((offset < 0) || (static_cast<size_t>(offset) >= overwrittenSize)) {
        // Target is to outside of the overwritten area.
        CatValue<uint32>(ppWriter, target - (reinterpret_cast<uint32>(*ppWriter) + sizeof(uint32)));
      }
      else {
        // Target is to inside of the overwritten area, so it needs to point inside of the trampoline.
        // It might be a later instruction we haven't copied yet, so we have to fix this up as a post-process.
        deferredRelocs.emplace_back(reinterpret_cast<uint32*>(*ppWriter), static_cast<uint8>(offset));
        CatValue<uint32>(ppWriter, 0x00000000);
      }
    }
  }

  for (const auto& reloc : deferredRelocs) {
    *(reloc.first) = PcRelPtr(reloc.first, 4, (pBegin + offsetLut[reloc.second]));
  }
}

// =====================================================================================================================
static Status CreateTrampoline(
  void*    pAddress,
  void**   ppAllocation,                          // [out] Address of where trampoline code begins.
  void**   ppTrampoline,                          // [out] Raw unaligned address of allocation.
  uint8*   pOverwrittenSize,                      // [out] Total size in bytes of overwritten instructions.
  size_t*  pTrampolineSize,                       // [out] Size in bytes of trampoline allocation.
  size_t   prologSize                  = 0,       // [in]  Bytes to prepend before the trampoline. Used by LowLevelHook.
  uint8    offsetLut[MaxOverwriteSize] = nullptr) // [out] LUT of overwritten instruction offsets to trampoline offsets.
{
  assert((pAddress != nullptr) && (ppAllocation != nullptr) && (pOverwrittenSize != nullptr));
  assert((prologSize % CodeAlignment) == 0);

  csh       hDisassembler;
  cs_insn*  pInsns = nullptr;
  size_t    count  = 0;

#if PATCHER_X86_32
  Status status = TranslateCsError(cs_open(CS_ARCH_X86, CS_MODE_32, &hDisassembler));
#else
  Status status = Status::FailUnsupported;
#endif
  const bool csOpened = (status == Status::Ok);

  if (status == Status::Ok) {
    // We need to disassemble at most sizeof(Jmp32) instructions.
    count = cs_disasm(hDisassembler,
                      static_cast<const uint8*>(pAddress),
                      (sizeof(pInsns->bytes) * sizeof(Jmp32)),
                      reinterpret_cast<uintptr_t>(pAddress),
                      sizeof(Jmp32),
                      &pInsns);

    status = (count != 0) ? TranslateCsError(cs_errno(hDisassembler)) : Status::FailDisassemble;
  }

  void*  pAllocation = nullptr;
  void*  pTrampoline = nullptr;
  size_t allocSize   = 0;

  uint32 oldCount        = 0;
  uint8  overwrittenSize = 0;

  if (status == Status::Ok) {
    // Calculate how many instructions will actually be overwritten by the Jmp32 and their total size.
    bool foundEnd = false;
    const auto IsPad = [](const cs_insn& insn)
      { return ((insn.id == X86_INS_INT3) || (insn.id == X86_INS_NOP) || ((insn.bytes[0] == 0) && (insn.size == 1))); };

    for (uint32 i = 0; ((i < count) && (overwrittenSize < sizeof(Jmp32))); ++i) {
      if (foundEnd && (IsPad(pInsns[i]) == false)) {
        break;
      }

      overwrittenSize += pInsns[i].size;

      if (foundEnd == false) {
        ++oldCount;

        if ((pInsns[i].id == X86_INS_RET) || (pInsns[i].id == X86_INS_RETF) || (pInsns[i].id == X86_INS_RETFQ)) {
          // Assume a return instruction is the end of a branch or the function.
          foundEnd = true;
        }
      }
    }

    if (overwrittenSize >= sizeof(Jmp32)) {
      *pOverwrittenSize = overwrittenSize;
    }
    else if (overwrittenSize >= 2) {
      status = Status::FailDisassemble;

      // Count how many alignment padding bytes are before the function.  If we have enough space for a Jmp32 in there,
      // we can overwrite the start of the function with a 2-byte jmp to the jmp32.
      uint8* pReader = static_cast<uint8*>(pAddress);

      // Padder bytes are typically int 3 (0xCC), nop (0x90), or NUL.
      for (int32 i = 1; ((pReader[-i] == 0xCC) || (pReader[-i] == 0x90) || (pReader[-i] == 0x00)); ++i) {
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
    pAllocation = g_allocator.Alloc(allocSize);

    if (pAllocation != nullptr) {
      // HeapAlloc has a fixed allocation alignment (typically 8 bytes), but we need 16-byte alignment.  We might have
      // to pad the allocation ourselves.
      pTrampoline = reinterpret_cast<void*>(Align(reinterpret_cast<uintptr_t>(pAllocation), CodeAlignment));

      const uint8 alignPadLen = static_cast<uint8>(PtrDelta(pTrampoline, pAllocation));

      // Fill in alignment padding with int 3.
      if (alignPadLen > 0) {
        memset(pAllocation, 0xCC, alignPadLen);
      }
    }
    else {
      status = Status::FailMemAlloc;
    }
  }

  if (status == Status::Ok) {
    uint8 localOffsetLut[MaxOverwriteSize];
    if (offsetLut == nullptr) {
      memset(&localOffsetLut[0], 0, sizeof(localOffsetLut));
      offsetLut = localOffsetLut;
    }

    // Our trampoline needs to be able to reissue instructions overwritten by the jump to it.
    uint8* pWriter = (static_cast<uint8*>(pTrampoline) + prologSize);
    CopyInstructions(&pWriter, pInsns, &oldCount, &overwrittenSize, offsetLut);

    // Complete the trampoline by writing a jmp instruction to the original function.
    CatValue<Jmp32>(&pWriter, { 0xE9, PcRelPtr(pWriter, sizeof(Jmp32), PtrInc(pAddress, *pOverwrittenSize)) });

    // Fill in any left over bytes with int 3 padders.
    const size_t remainingSize = allocSize - PtrDelta(pWriter, pAllocation);
    if (remainingSize > 0) {
      memset(pWriter, 0xCC, remainingSize);
    }
  }

  if (pInsns != nullptr) {
    cs_free(pInsns, count);
  }

  if (csOpened) {
    status = TranslateCsError(cs_close(&hDisassembler));
  }

  if ((status != Status::Ok) && (pAllocation != nullptr)) {
    g_allocator.Free(pAllocation);
    pTrampoline = nullptr;
  }

  if (status == Status::Ok) {
    *ppAllocation    = pAllocation;
    *ppTrampoline    = pTrampoline;
    *pTrampolineSize = allocSize;
  }

  return status;
}

// =====================================================================================================================
Status PatchContext::Hook(
  TargetPtr    pAddress,
  FunctionPtr  pfnNewFunction,
  void*        pPfnTrampoline)
{
#if (PATCHER_X86_32 == false)
  status_ = Status::FailUnsupported;
#endif

  void*const pDst = MaybeRelocateTargetPtr(this, pAddress);

  void*  pTrampoline     = nullptr;
  void*  pTrampolineMem  = nullptr;
  uint8  overwrittenSize = 0;
  size_t trampolineSize  = 0;

  if (pPfnTrampoline != nullptr) {
    auto it = historyAt_.find(pDst);
    if ((status_ == Status::Ok) && (it != historyAt_.end())) {
      auto& pTrackedTrampoline = std::get<2>(*it->second);

      if (pTrackedTrampoline != nullptr) {
        // Destroy the existing trampoline.
        Revert(pDst);
      }
    }

    if (status_ == Status::Ok) {
      status_ = CreateTrampoline(pDst, &pTrampolineMem, &pTrampoline, &overwrittenSize, &trampolineSize);
    }
  }
  else {
    overwrittenSize = sizeof(Jmp32);
  }

  if (status_ == Status::Ok) {
    if (overwrittenSize >= sizeof(Jmp32)) {
#pragma pack(push, 1)
      struct {
        Jmp32 jmpToHookFunction;
        uint8 pad[MaxOverwriteSize - sizeof(Jmp32)];
      } jmp32;
#pragma pack(pop)

      jmp32.jmpToHookFunction = { 0xE9, PcRelPtr(pDst, sizeof(Jmp32), pfnNewFunction) };

      if (overwrittenSize > sizeof(Jmp32)) {
        // Write no-ops if an instruction is partially overwritten if we are generating a trampoline.
        memset(&jmp32.pad[0], 0x90, sizeof(jmp32.pad));
      }

      Memcpy(pDst, &jmp32, overwrittenSize);
    }
    else if (overwrittenSize >= 2) {
      // There isn't enough space for a jmp32 at pAddress, but there is in the padding bytes preceding it.
#pragma pack(push, 1)
      struct {
        Jmp32 jmpToHookFunction;
        Jmp8  jmpToPreviousInsn;
        uint8 pad[MaxOverwriteSize - (sizeof(Jmp32) + sizeof(Jmp8))];
      } indirectJmp32;
#pragma pack(pop)

      indirectJmp32.jmpToHookFunction = { 0xE9, static_cast<uint32>(PtrDelta(pfnNewFunction, pDst)) };
      indirectJmp32.jmpToPreviousInsn =
        { 0xEB, PcRelPtr<int8>(&indirectJmp32.jmpToPreviousInsn, sizeof(Jmp8), &indirectJmp32.jmpToHookFunction) };

      if (overwrittenSize > 2) {
        // Write no-ops if an instruction is partially overwritten if we are generating a trampoline.
        memset(&indirectJmp32.pad[0], 0x90, sizeof(indirectJmp32.pad));
      }

      void*const pPatchAddr = PtrDec(pDst, sizeof(Jmp32));
      Memcpy(pPatchAddr, &indirectJmp32, (overwrittenSize + sizeof(Jmp32)));

      if (status_ == Status::Ok) {
        // Fix up the lookup address key in the historyAt_ map so we can still revert by the user-supplied address.
        auto it = historyAt_.find(pPatchAddr);
        historyAt_[pDst] = it->second;
        historyAt_.erase(it);
      }
    }
    else {
      status_ = Status::FailDisassemble;
    }
  }

  if ((status_ == Status::Ok) && (pPfnTrampoline != nullptr)) {
    auto& entry = *historyAt_[pDst];
    auto& pTrackedTrampoline    = std::get<2>(entry);
    auto& trackedTrampolineSize = std::get<3>(entry);

    // Add trampoline info to the history tracker entry for this patch so we can clean it up later.
    pTrackedTrampoline    = pTrampolineMem;
    trackedTrampolineSize = trampolineSize;

    *static_cast<void**>(pPfnTrampoline) = pTrampoline;
  }

  if ((status_ != Status::Ok) && (pTrampolineMem != nullptr)) {
    g_allocator.Free(pTrampolineMem);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::HookCall(
  TargetPtr    pAddress,
  FunctionPtr  pfnNewFunction)
{
#if (PATCHER_X86_32 == false)
  status_ = Status::FailUnsupported;
#endif

  void*const pDst = MaybeRelocateTargetPtr(this, pAddress);
  const auto*const pInsn = static_cast<uint8*>(pDst);

  if (pInsn[0] == 0xE8) {
    // Call pcrel32
    Write(pDst,  Call32{ 0xE8, PcRelPtr(pDst, sizeof(Call32), pfnNewFunction) });
  }
  else if ((pInsn[0] == 0xFF) && (pInsn[1] == 0x15)) {
    // Call m32
    struct {
      Call32  call;
      uint8   pad;
    } code;
    code.call = { 0xE8, PcRelPtr(pDst, sizeof(Call32), pfnNewFunction) };
    code.pad  = 0x90;

    Write(pDst, code);
  }
  else {
    status_ = Status::FailInvalidPointer;
  }

  return status_;
}

// =====================================================================================================================
// Helper function to generate low-level hook trampoline code.
static size_t CreateLowLevelHookTrampoline(
  void*                         pLowLevelHook,
  const std::vector<Register>&  registers,
  uint32                        byRefMask,
  const void*                   pAddress,
  const void*                   pfnHookCb,
  ptrdiff_t                     moduleRelocDelta,
  const uint8                   (&offsetLut)[MaxOverwriteSize],
  uint8                         overwrittenSize,
  uint32                        options)
{
  struct Insn {
    uint8   bytes[2];
    size_t  sizeInBytes = 1;
  };
#if PATCHER_X86_32 //                        Eax:    Ecx:    Edx:    Ebx:    Esi:    Edi:    Ebp:    Esp:    Eflags:
  static constexpr Insn     PushInsns[] = { {0x50}, {0x51}, {0x52}, {0x53}, {0x56}, {0x57}, {0x55}, {0x54}, {0x9C} };
  static constexpr Insn     PopInsns[]  = { {0x58}, {0x59}, {0x5A}, {0x5B}, {0x5E}, {0x5F}, {0x5D}, {0x5C}, {0x9D} };
  static constexpr Register VolatileRegisters[] = { Register::Eflags, Register::Ecx, Register::Edx, Register::Eax };
  static constexpr Register ReturnRegister      = Register::Eax;
  static constexpr Register StackRegister       = Register::Esp;
  static constexpr Register ByReference         = Register::Count;  // Placeholder for args by reference.

  // Fix user-provided byRefMask such that UINT_MAX = all registers.
  const uint32 highBit = (1u << (registers.size() - 1));
  byRefMask = registers.empty() ? 0 : (byRefMask & (highBit | (highBit - 1u)));

  std::vector<Register> stackRegisters;  // Registers, in order they are pushed to the stack in (RTL).
  stackRegisters.reserve(registers.size() + ArrayLen(VolatileRegisters) + PopCount(byRefMask));
  uint32 returnRegIndex = UINT_MAX;
  uint32 stackRegIndex  = UINT_MAX;
  uint32 firstArgIndex  = 0;

  const auto AddRegisterToStack = [&stackRegisters, &returnRegIndex, &stackRegIndex](Register reg) {
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
  if (registers.empty() == false) {
    for (uint32 i = 0; i < registers.size(); ++i) {
      assert(registers[i] < Register::Count);
      requestedRegMask |= (1 << static_cast<uint32>(registers[i]));
    }
  }
  for (const Register reg : VolatileRegisters) {
    if (BitFlagTest(requestedRegMask, 1 << static_cast<uint32>(reg)) == false) {
      AddRegisterToStack(reg);
    }
  }

  if (registers.empty() == false) {
    // Registers by reference must be pushed prior to function args;  references to them are pushed alongside the args.
    for (uint32 i = 0, mask = byRefMask; BitScanFwdIter(&i, mask); mask &= ~(1 << i)) {
      AddRegisterToStack(registers[i]);
    }

    // Push the function args the user-provided callback will actually see now.
    firstArgIndex = stackRegisters.size();
    for (size_t i = registers.size(); i > 0; --i) {
      const size_t index = i - 1;
      AddRegisterToStack(BitFlagTest(byRefMask, 1 << index) ? ByReference : registers[index]);
    }

    if (BitFlagTest(options, LowLevelHookOpt::ArgsAsStructPtr)) {
      // Pushing ESP last is equivalent of pushing a pointer to everything before it on the stack.
      AddRegisterToStack(StackRegister);
    }
  }

  // Write the low-level hook trampoline code.
  uint8* pWriter = static_cast<uint8*>(pLowLevelHook);

  const auto Push = [&pWriter](Register r)
    { CatBytes(&pWriter, &PushInsns[static_cast<uint32>(r)].bytes[0], PushInsns[static_cast<uint32>(r)].sizeInBytes); };
  const auto Pop = [&pWriter](Register r)
    { CatBytes(&pWriter, &PopInsns[static_cast<uint32>(r)].bytes[0],  PopInsns[static_cast<uint32>(r)].sizeInBytes);  };

  Register   spareRegister   = Register::Count;
  const auto PushAdjustedEsp = [&pWriter, &stackRegisters, &spareRegister, &Push](size_t index, size_t offset) {
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

      if (spareRegister != Register::Count) {  // Eax:  Ecx:  Edx:  Ebx:  Esi:  Edi:
        static constexpr uint8 LeaOperands[] = { 0x44, 0x4C, 0x54, 0x5C, 0x74, 0x7C, };
        const uint32 index = static_cast<uint32>(spareRegister);
        CatBytes(&pWriter, { 0x8D, LeaOperands[index], 0x24, static_cast<uint8>(4 * offset) });  // lea  r32, [esp + i8]
        Push(spareRegister);                                                                     // push r32
      }
      else
      {
        // No spare registers.  Push stack pointer then adjust it on the stack in-place.  May be slower.
        Push(StackRegister);                                                       // push esp
        CatBytes(&pWriter, { 0x83, 0x04, 0x24, static_cast<uint8>(4 * offset) });  // add  dword ptr [esp], i8
      }
    }
  };

  // Push required registers to the stack in RTL order, per the cdecl calling convention.
  uint8 numReferencesPushed = 0;
  for (auto it = stackRegisters.begin(); it != stackRegisters.end(); ++it) {
    const Register reg = *it;
    if (reg == StackRegister) {
      PushAdjustedEsp(stackRegIndex, stackRegIndex);
    }
    else if (reg != ByReference) {
      Push(reg);  // push r32
    }
    else {
      // Register by reference.
      const size_t index  = (it - stackRegisters.begin());
      const size_t offset = (index - firstArgIndex) + (numReferencesPushed++);
      assert(index >= firstArgIndex);
      PushAdjustedEsp(index, offset);
    }
  }

  // Write the call instruction to our hook callback function.
  // If return value == nullptr, or custom return destinations aren't allowed, we can take a simpler path.
  CatValue(&pWriter, Call32{ 0xE8, PcRelPtr(pWriter, sizeof(Call32), pfnHookCb) });  // call pcrel32
  if (BitFlagTest(options, LowLevelHookOpt::NoCustomReturnAddr) == false) {
    CatBytes(&pWriter, { 0x85, 0xC0,                                                 // test eax, eax
                         0x75, 0x00 });                                              // jnz  short i8
  }
  auto*const pSkipCase1Offset = (pWriter - 1);  // This will be set later when we know the size.

  const auto WriteSkipPop = [&pWriter, pLowLevelHook]() {
    constexpr uint8 SkipPop[] = { 0x83, 0xC4, 0x04 };  // add esp, 0x4
    if ((PtrDelta(pWriter, pLowLevelHook) >= 3) &&
        (pWriter[-3] == SkipPop[0]) && (pWriter[-2] == SkipPop[1]) && ((pWriter[-1] + SkipPop[2]) <= INT8_MAX))
    {
      // Combine adjacent skips.
      pWriter[-1] += SkipPop[2];
    }
    else {
      CatValue(&pWriter, SkipPop);
    }
  };

  // Case 1: Return to original destination (hook function returned nullptr, or custom returns are disabled)
  // (Re)store register values from the stack.
  for (auto it = stackRegisters.rbegin(); it != stackRegisters.rend(); ++it) {
    const Register reg = *it;
    if (((stackRegIndex == 0) || (reg != StackRegister)) && (reg != ByReference)) {
      Pop(reg);  // pop r32
    }
    else {
      // Skip this arg.  (If this is the stack register, it will be popped later.)
      WriteSkipPop();
    }
  }

  if (BitFlagTest(requestedRegMask, 1 << static_cast<uint32>(StackRegister)) && (stackRegIndex != 0)) {
    // (Re)store ESP.
    const uint8 offset = static_cast<uint8>(-4 * (stackRegIndex + 1));
    CatBytes(&pWriter, { 0x8B, 0x64, 0x24, offset });  // mov esp, dword ptr [esp + i8]
  }

  // Jump to the trampoline to the original function.
  void*const pTrampolineToOld = PtrInc(pLowLevelHook, MaxLowLevelHookSize);
  CatValue(&pWriter, Jmp32{ 0xE9, PcRelPtr(pWriter, sizeof(Jmp32), pTrampolineToOld) }); // jmp pcrel32

  if (BitFlagTest(options, LowLevelHookOpt::NoCustomReturnAddr) == false) {
    // Write the skip branch jmp offset now that we know the end of this branch.
    *pSkipCase1Offset = static_cast<uint8>(PtrDelta(pWriter, pSkipCase1Offset) - 1);

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
    CatValue(&pWriter, RelocateIntoTrampolineCodeChunkImage);
    pRelocateCode->testAfterOverwrite.operand = reinterpret_cast<uint32>(PtrInc(pAddress, overwrittenSize));
    pRelocateCode->branch1.testBeforeOverwrite.operand         = reinterpret_cast<uint32>(pAddress);
    pRelocateCode->branch1.branch1A.subtractOldAddress.operand = reinterpret_cast<uint32>(pAddress);
    // We will defer initializing the offset LUT lookup operand until we know where the LUT will be placed.
    pRelocateCode->branch1.branch1A.addTrampolineToOld.operand = reinterpret_cast<uint32>(pTrampolineToOld);

    // (Re)store register values from the stack.
    for (auto it = stackRegisters.rbegin(); it != stackRegisters.rend(); ++it) {
      const Register reg = *it;
      if (reg == ReturnRegister) {
        // EAX is being used to hold our return address, so it needs to be special cased.
        if (returnRegIndex != 0) {
          assert(returnRegIndex != UINT_MAX);
          WriteSkipPop();
        }
      }
      else if ((reg == ByReference) || (reg == StackRegister)) {
        // Skip arg references; we only care about the actual values they point to further up the stack.
        // Skip ESP.  If it was user-requested, we have a chance to restore it after all other args have been popped.
        WriteSkipPop();
      }
      else {
        Pop(reg);  // pop r32
      }
    }

    if (BitFlagTest(requestedRegMask, 1 << static_cast<uint32>(StackRegister))) {
      // ** TODO Implement overwriting ESP in the custom return destination path.
      // Not asserting or erroring out here, so that calling this function with byRefMask = 0xFFFFFFFF is always valid.
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

    // Initialize the offset LUT lookup instruction we had deferred, now that we know where we're copying the LUT to.
    pRelocateCode->branch1.branch1A.offsetTableLookup.operand = reinterpret_cast<uint32>(pWriter);
    // Copy the offset lookup table.
    CatBytes(&pWriter, &offsetLut[0], sizeof(offsetLut));
  }

  const size_t size = PtrDelta(pWriter, pLowLevelHook);
  assert(size <= MaxLowLevelHookSize);
  return size;
#else
  // Unsupported instruction set.
  assert(false);
  return 0;
#endif
}

// =====================================================================================================================
Status PatchContext::LowLevelHook(
  TargetPtr                     pAddress,
  const std::vector<Register>&  registers,
  uint32                        byRefMask,
  FunctionPtr                   pfnHookCb,
  uint32                        options)
{
  void*const pDst = MaybeRelocateTargetPtr(this, pAddress);

  void*  pTrampoline     = nullptr;
  void*  pTrampolineMem  = nullptr;
  uint8  overwrittenSize = 0;
  size_t trampolineSize  = 0;
  uint8  offsetLut[MaxOverwriteSize] = { };

#if (PATCHER_X86_32 == false)
  status_ = Status::FailUnsupported;
#endif

  auto it = historyAt_.find(pDst);
  if ((status_ == Status::Ok) && (it != historyAt_.end())) {
    auto& pTrackedTrampoline = std::get<2>(*it->second);

    if (pTrackedTrampoline != nullptr) {
      // Destroy the existing trampoline.
      Revert(pDst);
    }
  }

  if (status_ == Status::Ok) {
    status_ = CreateTrampoline(
      pDst, &pTrampolineMem, &pTrampoline, &overwrittenSize, &trampolineSize, MaxLowLevelHookSize, offsetLut);
  }

  if (status_ == Status::Ok) {
    if ((pTrampoline != nullptr) && (overwrittenSize >= sizeof(Jmp32))) {
      // Initialize low-level hook code.
      const size_t usedSize = CreateLowLevelHookTrampoline(pTrampoline,
                                                           registers,
                                                           byRefMask,
                                                           pDst,
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
      jmp.instruction = { 0xE9, PcRelPtr(pDst, sizeof(Jmp32), pTrampoline) };
      if (overwrittenSize > sizeof(Jmp32)) {
        // Write no-ops if an instruction is partially overwritten.
        memset(&jmp.pad[0], 0x90, sizeof(jmp.pad));
      }

      Memcpy(pDst, &jmp, overwrittenSize);
    }
    else {
      status_ = Status::FailDisassemble;
    }
  }

  if (status_ == Status::Ok) {
    auto& entry = *historyAt_[pDst];
    auto& pTrackedTrampoline    = std::get<2>(entry);
    auto& trackedTrampolineSize = std::get<3>(entry);

    // Add trampoline info to the history tracker entry for this patch so we can clean it up later.
    pTrackedTrampoline    = pTrampolineMem;
    trackedTrampolineSize = trampolineSize;
  }

  if ((status_ != Status::Ok) && (pTrampolineMem != nullptr)) {
    g_allocator.Free(pTrampolineMem);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::EditExports(
  const std::vector<ExportInfo>&  exportInfos)
{
#if (PATCHER_X86_32 == false)
  status_ = Status::FailUnsupported;
#endif

  IMAGE_DATA_DIRECTORY*const pExportDataDir = GetDataDirectory(hModule_, IMAGE_DIRECTORY_ENTRY_EXPORT);

  if ((status_ == Status::Ok) && (pExportDataDir == nullptr)) {
    // Not a valid PE image.
    status_ = Status::FailInvalidModule;
  }

  if (status_ == Status::Ok) {
    std::vector<void*>          exports;
    std::unordered_set<uint32>  forwardExportOrdinals;

    std::map<std::string, uint32> namesToOrdinals;

    IMAGE_EXPORT_DIRECTORY* pOldExportTable = nullptr;
    char moduleName[512] = "";

    if ((pExportDataDir->VirtualAddress == 0) || (pExportDataDir->Size == 0)) {
      // Module has no export table.
      GetModuleFileNameA(static_cast<HMODULE>(hModule_), &moduleName[0], sizeof(moduleName));
      exports.reserve(exportInfos.size());
    }
    else {
      // Module has an export table.
      pOldExportTable = static_cast<IMAGE_EXPORT_DIRECTORY*>(PtrInc(hModule_, pExportDataDir->VirtualAddress));
      strncpy_s(
        &moduleName[0], sizeof(moduleName), static_cast<char*>(PtrInc(hModule_, pOldExportTable->Name)), _TRUNCATE);

      auto*const pFunctions    = static_cast<uint32*>(PtrInc(hModule_, pOldExportTable->AddressOfFunctions));
      auto*const pNames        = static_cast<uint32*>(PtrInc(hModule_, pOldExportTable->AddressOfNames));
      auto*const pNameOrdinals = static_cast<uint16*>(PtrInc(hModule_, pOldExportTable->AddressOfNameOrdinals));

      // Copy the module's exports.
      exports.reserve(pOldExportTable->NumberOfFunctions + exportInfos.size());
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
    for (uint32 i = 0, nextIndex = (exports.empty() ? 0 : (exports.size())); i < exportInfos.size(); ++i) {
      while ((exports.size() > nextIndex) && (exports[nextIndex] != nullptr)) {
        // Fix up next export ordinal, in the case of having added an export by ordinal.
        ++nextIndex;
      }

      auto curExport = exportInfos[i];
      switch (curExport.type) {
      case ExportInfo::ByNameFix:
        curExport.pAddress = (curExport.address != 0) ? FixPtr(curExport.address) : nullptr;
      case ExportInfo::ByName:
        assert(curExport.pSymbolName != nullptr);
        if (curExport.pAddress != nullptr) {
          exports.emplace_back(curExport.pAddress);
          namesToOrdinals[curExport.pSymbolName] = nextIndex++;
        }
        else {
          namesToOrdinals.erase(curExport.pSymbolName);
        }
        break;

      case ExportInfo::ByOrdinalFix:
        curExport.pAddress = (curExport.address != 0) ? FixPtr(curExport.address) : nullptr;
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
        assert((curExport.pSymbolName != nullptr) && (curExport.pForwardName != nullptr));
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
      auto*const  pAddressTable        = static_cast<uint32*>(PtrInc(pAllocation,     HeaderSize));        // By RVA
      auto*       pNameTable           = static_cast<uint32*>(PtrInc(pAddressTable,   addressTableSize));  // By RVA
      auto*       pNameOrdinalTable    = static_cast<uint16*>(PtrInc(pNameTable,      namePtrTableSize));
      auto*       pStringBuffer        = static_cast<char*>(PtrInc(pNameOrdinalTable, nameOrdinalTableSize));
      auto*       pForwardStringBuffer = static_cast<char*>(PtrInc(pStringBuffer,     totalNameStrlen));

      // Initialize the Export Directory Table header.
      pHeader->Characteristics       = (pOldExportTable != nullptr) ? pOldExportTable->Characteristics : 0;
      pHeader->TimeDateStamp         = (pOldExportTable != nullptr) ? (pOldExportTable->TimeDateStamp + 1) : 0;
      pHeader->MajorVersion          = (pOldExportTable != nullptr) ? pOldExportTable->MajorVersion : 0;
      pHeader->MinorVersion          = (pOldExportTable != nullptr) ? pOldExportTable->MinorVersion : 0;
      pHeader->Name                  = static_cast<DWORD>(PtrDelta(pStringBuffer, hModule_));  // By RVA
      pHeader->Base                  = (pOldExportTable != nullptr) ? pOldExportTable->Base : 1;
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
        auto& entry = *historyAt_[pExportDataDir];
        auto& pTrackedExportTableAllocation = std::get<2>(entry);
        auto& trackedExportTableAllocSize   = std::get<3>(entry);

        // Add export table allocation info to the history tracker entry for this patch so we can clean it up later.
        pTrackedExportTableAllocation = pAllocation;
        trackedExportTableAllocSize   = allocSize;
      }
    }
    else {
      status_ = Status::FailMemAlloc;
    }
  }

  return status_;
}

} // Patcher
