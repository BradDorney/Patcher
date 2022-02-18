/*
 ***********************************************************************************************************************
 * Copyright (c) 2022, Brad Dorney
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
#include <limits>
#include <mutex>

#include <unordered_set>
#include <map>
#include <string>
#include <deque>

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

// Internal macros

#define PATCHER_PACK_STRUCT      PATCHER_PRAGMA(pack(push, 1))
#define PATCHER_END_PACK_STRUCT  PATCHER_PRAGMA(pack(pop))

#if PATCHER_X86_32
# define IF_X86_32(...)  __VA_ARGS__
#else
# define IF_X86_32(...)
#endif
#if PATCHER_X86_64
# define IF_X86_64(...)  __VA_ARGS__
#else
# define IF_X86_64(...)
#endif

// Internal typedefs

using Status     = PatcherStatus;
using InsnVector = std::vector<cs_insn>;

PATCHER_PACK_STRUCT
// Generic structure of a simple x86 instruction with one opcode and one operand.
template <size_t OpcodeSize, typename OperandType, uint8... DefaultOpcode>
struct Op {
  using OpcodeType = Conditional<OpcodeSize == 1, uint8, uint8[OpcodeSize]>;
  OpcodeType  opcode = { DefaultOpcode... };
  OperandType operand;
};

using Op1_4  = Op<1, uint32>;
using Op2_4  = Op<2, uint32>;
using Op1_8  = Op<1, uint64>;
using Op2_8  = Op<2, uint64>;
using Jmp8   = Op<1, int8,  0xEB>;  // Opcodes: 0xEB (unconditional), 0x7* & 0xE0-E3 (conditional)
using Jmp32  = Op<1, int32, 0xE9>;
using Call32 = Op<1, int32, 0xE8>;

struct Loop32 {
  constexpr Loop32(uint8 loopOpcode, int32 displacement)  // Opcodes: 0xE0-E3 (jecx, loop*)
    : loop{ loopOpcode, sizeof(ifFalse) }, ifFalse{ 0xEB, sizeof(ifTrue) }, ifTrue{ 0xE9, displacement } { }

  Jmp8  loop;     // (jecx/loop*) 2  (Go to Jmp32 if true)
  Jmp8  ifFalse;  // jmp 2           (Skip Jmp32 if false)
  Jmp32 ifTrue;
};

struct JmpAbs {
#if PATCHER_X86_32
  constexpr JmpAbs(uintptr address) : push{ 0x68, address }, retn(0xC3) { }

  Op1_4 push;  // push address
  uint8 retn;  // retn          (Note: return branch misprediction penalty)
#else
  constexpr JmpAbs(uintptr address) : jmp{ { 0xFF, 0x25 }, 0 }, address(address) { }

  Op2_4   jmp;      // jmp qword ptr [rip + 0]
  uintptr address;
#endif
};

struct JccAbs {
  constexpr JccAbs(uint8 jcc8Opcode, uintptr address)  // Opcodes: 0x7* & 0xE0-E3
    : jcc{ jcc8Opcode, sizeof(ifFalse) }, ifFalse{ 0xEB, sizeof(ifTrue) }, ifTrue(address) { }

  Jmp8   jcc;      // jcc 2  (Go to JmpAbs if true)
  Jmp8   ifFalse;  // jmp 2  (Skip JmpAbs if false)
  JmpAbs ifTrue;
};

struct CallAbs {
  constexpr CallAbs(uintptr address)
#if PATCHER_X86_32
    : pushRetnPtr{ 0xE8, 0 }, adjustRetnPtr{ 0x83, 0x04, 0x24, sizeof(CallAbs) - sizeof(pushRetnPtr) }, jmp(address) { }

  Call32 pushRetnPtr;       // call 0                    (Push return pointer (eip + sizeof(Call32)))
  uint8  adjustRetnPtr[4];  // add  dword ptr [esp], 10  (Adjust return pointer to be after jmp)
  JmpAbs jmp;               //                           (Note: return branch misprediction penalty)
#else
    : call{ { 0xFF, 0x15 }, sizeof(Jmp8) }, skipAddressData{ 0xEB, sizeof(address) }, address(address) { }

  Op2_4   call;             // call qword ptr [rip + 2]
  Jmp8    skipAddressData;  // jmp  8
  uintptr address;
#endif
};
PATCHER_END_PACK_STRUCT

// Internal constants

// x86 fetches instructions on 16-byte boundaries.  Allocated code should be aligned on these boundaries in memory.
constexpr uint32 CodeAlignment            = 16;
// Max instruction size on modern x86 is 15 bytes.
constexpr uint32 MaxInstructionSize       = 15;
// Copied instructions sometimes need to be translated to multiple instructions, which requires extra space.
constexpr uint32 MaxCopiedInstructionSize = uint32(Max(Max(MaxInstructionSize, sizeof(JccAbs)), sizeof(CallAbs)));
// Worst-case scenario is the last byte overwritten being the start of a MaxInstructionSize-sized instruction.
constexpr uint32 MaxOverwriteSize         = (IsX86_64 ? sizeof(JmpAbs) : sizeof(Jmp32)) + MaxInstructionSize - 1;

// Max size in bytes low-level hook trampoline code is expected to require.
constexpr uint32 MaxLowLevelHookSize  = Align(IsX86_64 ? 200 : 160, CodeAlignment);
// Max size in bytes functor thunk code is expected to require.
constexpr uint32 MaxFunctorThunkSize  = Align(IsX86_64 ? 64  : 32,  CodeAlignment);
// Number of extra args needed to call FunctionRef::InvokeFunctor().
constexpr uint32 InvokeFunctorNumArgs = 2;
// Max size in bytes far jump thunk code is expected to require.
constexpr uint32 FarThunkSize         = Align(uint32(Max(sizeof(JmpAbs), MaxFunctorThunkSize)), CodeAlignment);

constexpr uint32 OpenThreadFlags =
  (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION);

constexpr uint32 ExecutableProtectFlags =
  (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
constexpr uint32 ReadOnlyProtectFlags   = (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE);

// Internal utility functions and classes

// Returns true if any flags are set in mask.
template <typename T1, typename T2>  constexpr bool BitFlagTest(T1 mask, T2 flags) { return (mask & flags) != 0; }

// Aligns a pointer to the given power of 2 alignment.
static void*       PtrAlign(void*       p, size_t align)
  { return       reinterpret_cast<void*>(Align(reinterpret_cast<uintptr>(p), align)); }
static const void* PtrAlign(const void* p, size_t align)
  { return reinterpret_cast<const void*>(Align(reinterpret_cast<uintptr>(p), align)); }

// Returns true if value is at least aligned to the given power of 2 alignment.
template <typename T>
constexpr bool IsAligned(T value, size_t align) { return ((value & static_cast<T>(align - 1)) == 0); }

static bool IsPtrAligned(const void* ptr, size_t align) { return IsAligned(reinterpret_cast<uintptr>(ptr), align); }

// Returns true if a (program counter-relative) displacement exceeds 32-bit signed addressing.
constexpr bool IsFarDisplacement(ptrdiff_t displacement) { return IsX86_64 && (displacement != int32(displacement)); }

// Calculates a hash using std::hash.
template <typename T>  static size_t Hash(const T& src) { return std::hash<T>()(src); }

// Gets the OS system info, which includes memory allocator parameters.
static const SYSTEM_INFO& SystemInfo()
  { static SYSTEM_INFO si = []{ SYSTEM_INFO si;  GetSystemInfo(&si);  return si; }();  return si; }

// Helper functions to append string data (including null terminator) while incrementing a runner pointer.
static void AppendString(char** ppWriter, const char*       pSrc)
  { const size_t length = (strlen(pSrc) + 1);  strcpy_s(*ppWriter, length, pSrc);        *ppWriter += length; }
static void AppendString(char** ppWriter, const std::string& src)
  { const size_t length = (src.length() + 1);  strcpy_s(*ppWriter, length, src.data());  *ppWriter += length; }

// A very basic assembler class.  Writes machine code instructions to a given buffer.
class Assembler {
public:
  Assembler(void* pBuffer) : pBuffer_(pBuffer), pWriter_(static_cast<uint8*>(pBuffer)) { }

  Assembler& Byte(uint8 byte)                   { (pWriter_++)[0] = byte;                   return *this; }
  Assembler& ByteIf(bool condition, uint8 byte) { if (condition) { Byte(byte); }            return *this; }
  Assembler& Bytes(Span<uint8> bytes)
    { std::copy(bytes.begin(), bytes.end(), pWriter_);  pWriter_ += bytes.Length();         return *this; }
  Assembler& BytesIf(bool condition, Span<uint8> bytes) { if (condition) { Bytes(bytes); }  return *this; }

  Assembler& Memset(uint8 value, size_t size) { memset(pWriter_, value, size);  pWriter_ += size;  return *this; }

  template <typename T, typename = EnableIf<std::is_trivially_copyable<T>::value>>
  Assembler& Value(const T& value) { memcpy(pWriter_, &value, sizeof(T));  pWriter_ += sizeof(T);  return *this; }

  template <size_t OpcodeSize, typename OperandType, uint8... DefaultOpcode>
  Assembler& Op(const Patcher::Op<OpcodeSize, OperandType, DefaultOpcode...>& op) { Value(op);     return *this; }

  Assembler& Nop(size_t size = 1) {
    for (size_t remain = size, copySize; (copySize = Min(ArrayLen(NopTable), remain)) != 0; remain -= copySize) {
      memcpy(PtrInc(pWriter_, (remain - copySize)), &NopTable[copySize - 1], copySize);
    }
    pWriter_ += size;
    return *this;
  }

  Assembler& Push(Register reg) { return Bytes(PushInsns[size_t(reg)]); }
  Assembler& Pop(Register  reg) { return Bytes(PopInsns[size_t(reg)]);  }

  Assembler& PopNil(int32 count = 1) {
    // Use lea instead of add to avoid clobbering flags.
    if ((count <= (INT8_MAX / RegisterSize)) && (count != 0)) {
      constexpr uint8 SkipPop[] = { IF_X86_64(0x48,) 0x8D, 0x64, 0x24, 0x00 };  // lea esp, [esp + i8]
      const int8 skipSize = int8(count * RegisterSize);
      // Combine adjacent skips, otherwise write a new instruction.
      if ((GetPosition() < sizeof(SkipPop))                                                   ||
          (memcmp(&SkipPop[0], &pWriter_[-int32(sizeof(SkipPop))], sizeof(SkipPop) - 1) != 0) ||
          ((pWriter_[-1] + skipSize) > INT8_MAX))
      {
        Value(SkipPop);
      }
      pWriter_[-1] += skipSize;
    }
    else {
      Add(IF_X86_32(Register::Esp) IF_X86_64(Register::Rsp), (count * RegisterSize));
    }
    return *this;
  }

  Assembler& Add(Register reg, int32 value) {
    if (value != 0) {
      // Use lea instead of add to avoid clobbering flags.
      const bool  valueIs8Bit = (value == int8(value));
      const uint8 addOperand  = uint8(AddOperands[uint32(reg)] + (valueIs8Bit ? 0 : 0x40));
      Bytes({ IF_X86_64(uint8((reg < Register::R8) ? 0x48 : 0x4D),) 0x8D, addOperand });  // lea reg, [reg + value]
      ByteIf(IF_X86_32(reg == Register::Esp) IF_X86_64((reg == Register::Rsp) || (reg == Register::R12)), 0x24);
      valueIs8Bit ? Value(int8(value)) : Value(value);
    }
    return *this;
  }

  Assembler& LoadStackValue(Register   reg, int32 off) { return MovStack(0x8B, reg, off); } // mov reg, [esp + off]
  Assembler& LoadStackAddress(Register reg, int32 off) { return MovStack(0x8D, reg, off); } // lea reg, [esp + off]
  Assembler& StoreStackValue(Register  reg, int32 off) { return MovStack(0x89, reg, off); } // mov [esp + off], reg

  uint8& operator[](ptrdiff_t index) { return pWriter_[index]; }

  template <typename T = uint8*>  T GetNext() { return reinterpret_cast<T>(pWriter_); }

  void*  GetBuffer()         { return pBuffer_;                     }
  size_t GetPosition() const { return PtrDelta(pWriter_, pBuffer_); }

  template <typename T = ptrdiff_t>  T GetPcRelPtr(size_t fromSize, const void* pTo) const
    { return Patcher::PcRelPtr<T>(pWriter_, fromSize, pTo); }

private:
  using Insn = ConstArray<uint8, IsX86_64 ? 2 : 1>;
#if PATCHER_X86_32  //                      Eax:    Ecx:    Edx:    Ebx:    Esi:    Edi:    Ebp:    Esp:    Eflags:
  static constexpr Insn  PushInsns[]   = { {0x50}, {0x51}, {0x52}, {0x53}, {0x56}, {0x57}, {0x55}, {0x54}, {0x9C} };
  static constexpr Insn  PopInsns[]    = { {0x58}, {0x59}, {0x5A}, {0x5B}, {0x5E}, {0x5F}, {0x5D}, {0x5C}, {0x9D} };
  static constexpr uint8 SetOperands[] = {  0x44,   0x4C,   0x54,   0x5C,   0x74,   0x7C,   0x6C,   0x64 };
  static constexpr uint8 AddOperands[] = {  0x40,   0x49,   0x52,   0x5B,   0x76,   0x7F,   0x6D,   0x64 };
#elif PATCHER_X86_64
  static constexpr Insn PushInsns[] = {
  // Rax:    Rcx:    Rdx:    Rbx:    Rsi:    Rdi:    R8:           R9:           R10:          R11:
    {0x50}, {0x51}, {0x52}, {0x53}, {0x56}, {0x57}, {0x41, 0x50}, {0x41, 0x51}, {0x41, 0x52}, {0x41, 0x53},
  // R12:          R13:          R14:          R15:          Rbp:    Rsp:    Rflags:
    {0x41, 0x54}, {0x41, 0x55}, {0x41, 0x56}, {0x41, 0x57}, {0x55}, {0x54}, {0x9C}
  };
  static constexpr Insn PopInsns[]  = {
    {0x58}, {0x59}, {0x5A}, {0x5B}, {0x5E}, {0x5F}, {0x41, 0x58}, {0x41, 0x59}, {0x41, 0x5A}, {0x41, 0x5B},
    {0x41, 0x5C}, {0x41, 0x5D}, {0x41, 0x5E}, {0x41, 0x5F}, {0x5D}, {0x5C}, {0x9D}
  };
  static constexpr uint8 SetOperands[] =
  //  Rax:  Rcx:  Rdx:  Rbx:  Rsi:  Rdi:  R8:   R9:   R10:  R11:  R12:  R13:  R14:  R15:  Rbp:  Rsp:
    { 0x44, 0x4C, 0x54, 0x5C, 0x74, 0x7C, 0x44, 0x4C, 0x54, 0x5C, 0x64, 0x6C, 0x74, 0x7C, 0x6C, 0x64 };
  static constexpr uint8 AddOperands[] =
    { 0x40, 0x49, 0x52, 0x5B, 0x76, 0x7F, 0x40, 0x49, 0x52, 0x5B, 0x64, 0x7D, 0x76, 0x7F, 0x6D, 0x64 };
#endif
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

  Assembler& MovStack(uint8 opcode, Register reg, int32 offset) {
    const bool offsetIs8Bit = (offset == int8(offset));
    Bytes({ IF_X86_64(uint8((reg < Register::R8) ? 0x48 : 0x4C),) opcode });                    // mov or lea...
    offsetIs8Bit ? Bytes({ SetOperands[uint32(reg)], 0x24, uint8(offset) })                     // ... reg, [esp + i8]
                 : Op<2, int32>({ { uint8(SetOperands[uint32(reg)] + 0x40), 0x24 }, offset });  // ... reg, [esp + i32]
    return *this;
  }

  void*  pBuffer_;  // Starting pointer.
  uint8* pWriter_;  // Current pointer.
};

// Capstone disassembler helper class.  Disassembly reveals useful pathways.
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

  void Disassemble(const void* pAddress, size_t numInsns, InsnVector* pOut) const {
    if (refCount_ != 0) {
      cs_insn*      pInsns = nullptr;
      const size_t  count  = cs_disasm(
        hDisasm_, (const uint8*)(pAddress), sizeof(pInsns->bytes) * numInsns, uintptr(pAddress), numInsns, &pInsns);

      if (pInsns != nullptr) {
        if (GetLastError() == Status::Ok) {
          pOut->insert(pOut->end(), pInsns, pInsns + count);
        }
        cs_free(pInsns, count);
      }
    }
  }

  InsnVector Disassemble(const void* pAddress, size_t numInsns) const
    { InsnVector out;  Disassemble(pAddress, numInsns, &out);  return out; }

  Status GetLastError() const { return TranslateCsError(cs_errno(hDisasm_)); }

private:
  // Translates a Capstone error code to a PatcherStatus.
  static Status TranslateCsError(cs_err capstoneError) {
    switch (capstoneError) {
    case CS_ERR_OK:                          return Status::Ok;
    case CS_ERR_MEM:  case CS_ERR_MEMSETUP:  return Status::FailMemAlloc;
    default:                                 return Status::FailDisassemble;
    }
  }

  csh         hDisasm_;
  uint32      refCount_;
  std::mutex  lock_;
};

// Allocates memory such that it can be executed, and so that it is placed within 32-bit signed addressing.
class Allocator {
public:
   Allocator(void* pVaStart = nullptr) : pVaStart_(pVaStart), pNextBlock_(nullptr), refCount_(0) { }
  ~Allocator() { Deinit(); }

  void Acquire() { std::lock_guard<std::mutex> lock(lock_);      ++refCount_;                    }
  void Release() { std::lock_guard<std::mutex> lock(lock_);  if (--refCount_ == 0) { Deinit(); } }

  void* Alloc(size_t size, size_t align = CodeAlignment);
  void  Free(void* pMemory);

  static Allocator* GetInstance(const void* pNearAddr = nullptr) {
    static std::map<void*, Allocator> allocators;  // Map of pVaStart : allocator
    void*const pVaStart = reinterpret_cast<void*>(reinterpret_cast<uintptr>(pNearAddr) & ~VaRange);
    return &allocators.emplace(pVaStart, pVaStart).first->second;
  }

private:
  struct BlockHeader {
    void*  pNextAddr;  // Pointer to next allocation (unaligned).
    void*  pEndAddr;   // Pointer to just after the end of this block.
    uint32 refCount;   // Number of allocations from this block that are currently being referenced.
  };

  void Deinit() {
    for (auto* pSlab : pSlabs_) {
      VirtualFree(pSlab, 0, MEM_RELEASE);
    }
    pSlabs_.clear();
    pBlocks_.clear();
    pNextBlock_ = nullptr;
  }

  static size_t PageSize() { return SystemInfo().dwPageSize;              }  // Typically  4 KB
  static size_t SlabSize() { return SystemInfo().dwAllocationGranularity; }  // Typically 64 KB

  // Find an available region of VA space within 32-bit signed addressing.
  void* FindNextRegion(void* pNearAddr, size_t sizeNeeded);

  // Compare function to sort the pBlocks_ heap by free size.
  static bool FreeBlockSizeCompare(const BlockHeader* pFirst, const BlockHeader* pSecond)
    { return PtrDelta(pFirst->pEndAddr, pFirst->pNextAddr) < PtrDelta(pSecond->pEndAddr, pSecond->pNextAddr); }

  static constexpr uintptr VaRange = INT32_MAX;

  void* pVaStart_;    // Start of virtual address space within 32-bit signed addressing for memory allocations.
  void* pNextBlock_;  // Pointer to next block to commit, or past the end of the current slab.

  uint32     refCount_;
  std::mutex lock_;

  std::deque<void*>        pSlabs_;   // Reserved memory chunks, of multiples of SlabSize(), from oldest to newest.
  std::deque<BlockHeader*> pBlocks_;  // Max heap of committed memory pages, sorted by free size remaining.
};

// Internal globals

static Disassembler<CS_ARCH_X86, IsX86_64 ? CS_MODE_64 : CS_MODE_32>  g_disasm;

static std::mutex  g_freezeThreadsLock;


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
  pAllocator_(Allocator::GetInstance(hModule_)),
  status_(Status::FailInvalidModule)
{
  g_disasm.Acquire();
  pAllocator_->Acquire();  // ** TODO Very large modules (>2 GB) would need multiple allocators
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
  pAllocator_(Allocator::GetInstance(hModule_)),
  status_(Status::FailInvalidModule)
{
  g_disasm.Acquire();
  pAllocator_->Acquire();  // ** TODO Very large modules (>2 GB) would need multiple allocators
  InitModule();
}

// =====================================================================================================================
PatchContext::~PatchContext() {
  RevertAll();
  UnlockThreads();
  ReleaseModule();
  g_disasm.Release();
  if (pAllocator_ != nullptr) {
    pAllocator_->Release();  // ** TODO Very large modules (>2 GB) would need multiple allocators
  }
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

  if ((pDosHeader != nullptr)                      &&
      (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) &&
      (PtrInc<IMAGE_NT_HEADERS*>(hModule_, pDosHeader->e_lfanew)->Signature == IMAGE_NT_SIGNATURE))
  {
    // Calculate the module's base relocation delta.
    // The ImageBase field of the optional header gets overwritten, so we need to read the original file directly.
    wchar_t path[MAX_PATH] = L"";  // ** TODO This won't work with large paths

    if (GetModuleFileNameW(static_cast<HMODULE>(hModule_), &path[0], MAX_PATH) != 0) {
      path[MAX_PATH - 1] = L'\0';
      static constexpr uint32 ShareFlags = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
      HANDLE hFile =
        CreateFileW(&path[0], GENERIC_READ, ShareFlags, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);

      if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE)) {
        uint8 buf[Max(sizeof(IMAGE_NT_HEADERS), sizeof(IMAGE_NT_HEADERS64))];
        DWORD numRead = 0;

        if ((SetFilePointer(hFile, pDosHeader->e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) &&
            ReadFile(hFile, &buf[0], sizeof(buf), &numRead, nullptr)                                       &&
            (numRead >= sizeof(buf)))
        {
          const auto& peHeader = *reinterpret_cast<IMAGE_NT_HEADERS*>(&buf[0]);
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

        CloseHandle(hFile);
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
Status PatchContext::Write(
  TargetPtr           pAddress,
  const FunctionRef&  pfnNewFunction)
{
  if ((status_ == Status::Ok) && (pfnNewFunction == nullptr)) {
    status_ = Status::FailInvalidCallback;
  }

  if ((Write(pAddress, pfnNewFunction.Pfn()) == PatcherStatus::Ok) && (pfnNewFunction.Functor() != nullptr)) {
    auto& entry = *historyAt_[MaybeFixTargetPtr(pAddress)];
    entry.pFunctorObj     = pfnNewFunction.Functor();
    entry.pfnFunctorThunk = pfnNewFunction;
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
    Assembler(pAddress).Nop(size);
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

    Memcpy(entry.pAddress, entry.oldData.data(), entry.oldData.size());

    if (status_ == Status::Ok) {
      // Note: if Memcpy failed, tracked allocs won't get cleaned up until the trampoline allocation heap is destroyed.
      for (const auto& alloc : entry.trackedAllocs) {
        AdvanceThreads(alloc.first, alloc.second);
        pAllocator_->Free(alloc.first);
      }

      if (entry.pfnFunctorThunk != nullptr) {
        AdvanceThreads(entry.pfnFunctorThunk, MaxFunctorThunkSize);
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
    Memcpy(entry.pAddress, entry.oldData.data(), entry.oldData.size());

    if ((status_ == Status::Ok) || (status_ == Status::FailModuleUnloaded)) {
      // Note: if Memcpy failed, tracked allocs won't get cleaned up until the trampoline allocation heap is destroyed.
      for (const auto& alloc : entry.trackedAllocs) {
        AdvanceThreads(alloc.first, alloc.second);
        pAllocator_->Free(alloc.first);
      }

      if (entry.pfnFunctorThunk != nullptr) {
        AdvanceThreads(entry.pfnFunctorThunk, MaxFunctorThunkSize);
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
  g_freezeThreadsLock.lock();

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
    const bool ignored = g_freezeThreadsLock.try_lock();
    g_freezeThreadsLock.unlock();
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
  const void*  pAddress,
  size_t       size)
{
  if (size != 0) {
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
  }

  return status_;
}

// =====================================================================================================================
// ** TODO This needs to be able to handle saving and restoring non-POD data (from Assign() or Construct())
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
      history_.emplace_front(PatchInfo{ pAddress, DataStorage({ (uint8*)(pAddress), size }) });

      if ((history_.size() == oldSize) || (historyAt_.emplace(pAddress, history_.begin()).first == historyAt_.end())) {
        status_ = Status::FailMemAlloc;
      }
    }
    else {
      DataStorage& oldData = it->second->oldData;
      if (oldData.size() < size) {
        // Merge the original tracked data with the extra bytes we also need to track.
        oldData.Append({ PtrInc<uint8*>(pAddress, oldData.size()), (size - oldData.size()) });
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
    if ((hDstModule != NULL) && (hDstModule != hModule_)) {
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
      FlushInstructionCache(GetCurrentProcess(), pAddress, size);
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
          pAddress = reinterpret_cast<const void*>(static_cast<uintptr>(*static_cast<uint32*>(
            ((pHistoryData != nullptr) && (pHistoryData->size() == ptrSize)) ? pHistoryData->data() : ppAddress)));
        }
        else if (pRelocArray[i].type == IMAGE_REL_BASED_DIR64) {
          ptrSize  = 8;
          pAddress = reinterpret_cast<const void*>(*static_cast<uint64*>(
            ((pHistoryData != nullptr) && (pHistoryData->size() == ptrSize)) ? pHistoryData->data() : ppAddress));
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
    for (auto it =  (pRefsOut->begin() + startIndex); it != pRefsOut->end(); Revert(*(it++)));
    pRefsOut->erase((pRefsOut->begin() + startIndex), pRefsOut->end());
  }

  return status_;
}

// =====================================================================================================================
// Writes the code for a functor thunk.  Note that this function does not flush the instruction cache.
// Thunk translates from the function's calling convention to cdecl so it can call FunctionRef::InvokeFunctor().
static bool CreateFunctorThunk(
  void*              pMemory,
  const FunctionRef& pfnNewFunction)
{
  static constexpr uint8 PopSize = RegisterSize * (InvokeFunctorNumArgs - 1);

  Assembler writer(pMemory);
  bool result = (pMemory != nullptr);

  const uintptr            functorAddr = reinterpret_cast<uintptr>(pfnNewFunction.Functor().get());
  const RtFuncSig&         sig         = pfnNewFunction.Signature();
  const InvokeFunctorTable invokers    = pfnNewFunction.InvokerPfnTable();

  // ** TODO This should take into account the positions of the parameters, e.g. if (sizeof(param0) > RegisterSize) then
  //         params 1 and 2 would be the ones in registers
  size_t numRegisterSizeParams = 0;  // Number of parameters that can fit in a register (for the original function)
  for (uint32 i = 0; i < sig.numParams; (sig.pParamSizes[i++] <= RegisterSize) ? ++numRegisterSizeParams : 0);

  auto GetNumAlignmentPadders = [numRegisterSizeParams](size_t maxNumRegisterArgs = 0) {
    const size_t numExtraArgs = Min(numRegisterSizeParams, maxNumRegisterArgs);
    return InvokeFunctorMaxPad - ((InvokeFunctorNumArgs + numExtraArgs - 1) & InvokeFunctorMaxPad);
  };

  // We need to translate from the input calling convention to cdecl or stdcall, whichever closest matches caller/callee
  // cleanup behavior of the input.  We must push any register args used by the input, then push the functor obj address
  // and do the call.  Any expected caller-side cleanup instructions must be written after this.
  auto WriteCall = [&writer, &invokers, functorAddr](size_t numPadders = 0, bool calleeCleanup = false) {
    const void*const pfnInvokeFunctor =
      (IF_X86_32(calleeCleanup ? invokers.pfnInvokeWithPadAndCleanup :) invokers.pfnInvokeWithPad)[numPadders];

    if (IsX86_32) {
      writer.Op(Op1_4{ 0x68, uint32(functorAddr) })                                  // push pFunctor
            .BytesIf(numPadders, { 0x83, 0xEC, uint8(RegisterSize * numPadders) });  // sub  esp, i8  (Align ESP)
    }
    else if (IsX86_64) {
      numPadders += (IsMsAbi ? 4 : 0);  // MS x64 ABI expects 32 bytes of shadow space be allocated on the stack.
      writer.Op(Op2_8{ { 0x49, 0xBB }, functorAddr })                                     // movabs r11, pFunctor
            .Bytes({ 0x41, 0x53 })                                                        // push   r11
            .BytesIf(numPadders, { 0x48, 0x83, 0xEC, uint8(RegisterSize * numPadders) }); // sub    rsp, i8  (Align RSP)
    }

    if (calleeCleanup) {
      // Instead of using a call, which would return here, push the old return address to the top of the stack and jump.
      assert(IsX86_32);
      writer.Bytes({ 0xFF, 0x74, 0x24, uint8(RegisterSize * (numPadders + 1)) })            // push dword ptr [esp + i8]
            .Op(Jmp32{ 0xE9, writer.GetPcRelPtr<int32>(sizeof(Jmp32), pfnInvokeFunctor) }); // jmp  pfn
    }
    else {
      const ptrdiff_t callDelta = writer.GetPcRelPtr(sizeof(Call32), pfnInvokeFunctor);
      IsFarDisplacement(callDelta) ? writer.Op(Op2_8{ { 0x49, 0xBB }, uintptr(pfnInvokeFunctor) })  // movabs r11, pfn
                                           .Bytes({ 0x41, 0xFF, 0xD3 })                             // call   r11
                                   : writer.Op(Call32{ 0xE8, static_cast<int32>(callDelta) });      // call   pfn
    }
  };

  // Push args originally passed via registers to the stack.
  auto PushArgRegisters = [&writer, numRegisterSizeParams](Span<Register> registers)
    { for (size_t i = Min(numRegisterSizeParams, registers.Length()); i > 0; writer.Push(registers[--i])); };

  switch (sig.convention) {
#if PATCHER_X86_32
  case Call::Cdecl: {
    const size_t numAlignmentPadders = GetNumAlignmentPadders();
    WriteCall(numAlignmentPadders);
    writer.Bytes({ 0x83, 0xC4, uint8((numAlignmentPadders * RegisterSize) + PopSize), // add esp, i8  (Cleanup our args)
                   0xC3 });                                                           // retn
    break;
  }

  case Call::Stdcall:
    WriteCall(GetNumAlignmentPadders(), true);
    break;

  case Call::Thiscall:
    // MS thiscall puts the first register-sized arg in ECX.  If the arg exists, put it on the stack.
    if (numRegisterSizeParams >= 1) {
      writer.Pop(Register::Eax)    // pop  eax  (Pop old return address)
            .Push(Register::Ecx)   // push ecx  (Push arg passed via register)
            .Push(Register::Eax);  // push eax  (Push old return address)
    }
    WriteCall(GetNumAlignmentPadders(1), true);
    break;

  case Call::Fastcall:
    // MS fastcall puts the first 2 register-sized args in ECX and EDX.  If the args exist, put them on the stack.
    if (numRegisterSizeParams >= 1) {
      writer.Pop(Register::Eax);                           // pop  eax  (Pop old return address)
      PushArgRegisters({ Register::Ecx, Register::Edx });
      writer.Push(Register::Eax);                          // push eax  (Push old return address)
    }
    WriteCall(GetNumAlignmentPadders(2), true);
    break;

#elif PATCHER_X86_64
  case Call::Cdecl: {
    // The x64 calling convention passes the first 4 arguments via registers in MS ABI, or the first 6 in Unix ABI.
    const size_t numAlignmentPadders    = GetNumAlignmentPadders(InvokeFunctorNumSkipped);
    const size_t numRegArgs             = Min(numRegisterSizeParams, InvokeFunctorNumSkipped);
    const uint8  popPadAndInvokeArgSize = uint8((numAlignmentPadders * RegisterSize) + PopSize);
    const uint8  popRegArgSize          = uint8(numRegArgs * RegisterSize);

    if (numRegisterSizeParams >= 1) {
      // We need to pop the old return address (and the shadow space if MS ABI) before we can push our args.
      writer.Pop(Register::R11);                                      // pop  r11      (Pop old return address)
      if (IsMsAbi) {
        writer.Bytes({ 0x48, 0x83, 0xC4, uint8(RegisterSize * 4) });  // add  rsp, 32  (Pop old shadow space)
        PushArgRegisters({ Register::Rcx, Register::Rdx, Register::R8, Register::R9 });
      }
      else if (IsUnixAbi) {
        PushArgRegisters({ Register::Rsi, Register::Rdi, Register::Rdx, Register::Rcx, Register::R8, Register::R9 });
      }
      writer.Push(Register::R11);                                     // push r11      (Push old return address)
    }

    WriteCall(numAlignmentPadders);

    if (IsMsAbi) {
      // In MS ABI, we moved the shadow space, but the original caller will try to pop it, so we need to compensate.
      const uint8 totalPopSize = uint8(popPadAndInvokeArgSize + ((numRegArgs < 4) ? RegisterSize : 0) + popRegArgSize);
      const uint8 shadowOffset = uint8((RegisterSize * 3) - popRegArgSize);
      writer.Bytes({ 0x48, 0x83, 0xC4, totalPopSize })                     // add rsp, i8      (Cleanup our args)
            .BytesIf((numRegArgs < 4), { 0xFF, 0x74, 0x24, shadowOffset }) // push [rsp + i8]  (Push old return address)
            .Byte(0xC3);                                                   // retn             (Return)
    }
    else {
      writer.Bytes({ 0x48, 0x83, 0xC4, popPadAndInvokeArgSize })  // add  rsp, i8  (Cleanup padders and pFunctor)
            .Op<1, uint16>({ 0xC2, popRegArgSize });              // retn u16      (Return and finish cleanup)
    }
    break;
  }
#endif

  default:
    // Unknown or unsupported calling convention.
    result = false;
    break;
  }

  if (result) {
    const size_t sizeWritten = writer.GetPosition();
    assert(sizeWritten <= MaxFunctorThunkSize);
    if (sizeWritten < MaxFunctorThunkSize) {
      // Fill padding bytes with int 3 (breakpoint).
      writer.Memset(0xCC, MaxFunctorThunkSize - sizeWritten);
    }
  }

  return result;
}

// =====================================================================================================================
// Initializes the underlying function for FunctionRefs that have a state (capturing lambda or non-empty functor).
void FunctionRef::InitFunctorThunk(
  void*  pFunctorObj,
  void (*pfnDeleteFunctor)(void*))
{
  auto*const pAllocator = Allocator::GetInstance(pfnGetInvokers_);
  pAllocator->Acquire();
  void* pMemory = (pFunctorObj != nullptr) ? pAllocator->Alloc(MaxFunctorThunkSize, CodeAlignment) : nullptr;

  if (pMemory != nullptr) {
    // As the thunk is only valid while pObj_ is alive, its deleter will also deallocate the thunk.
    pObj_ = std::shared_ptr<void>(pFunctorObj, [pfnDeleteFunctor, pMemory, pAllocator](void* pObj)
      { pfnDeleteFunctor(pObj);  pAllocator->Free(pMemory);  pAllocator->Release(); });

    if (CreateFunctorThunk(pMemory, *this)) {
      pfn_ = pMemory;
      FlushInstructionCache(GetCurrentProcess(), pMemory, MaxFunctorThunkSize);
    }
  }
}

// =====================================================================================================================
// Finds if there's a region we can insert a hook patch, and what instructions will be overwritten.
static Status FindHookPatchRegion(
  void*       pAddress,
  uint8*      pOverwrittenSize,  // [out] Total size in bytes of overwritten instructions.
  InsnVector* pInsns,            // [out] Disassembled instructions in the region.
  size_t      maxPatchSize = IsX86_64 ? sizeof(JmpAbs) : sizeof(Jmp32))
{
  assert((pAddress != nullptr) && (pOverwrittenSize != nullptr));

  g_disasm.Disassemble(pAddress, maxPatchSize, pInsns);
  Status status = (pInsns->size() != 0) ? g_disasm.GetLastError() : Status::FailDisassemble;

  void*  pTrampoline = nullptr;
  size_t allocSize   = 0;

  uint32 oldCount        = 0;
  uint8  overwrittenSize = 0;
  uint32 bestCount       = 0;
  uint8  bestSize        = 0;

  if (status == Status::Ok) {
    // Calculate how many instructions will actually be overwritten by the Jmp32 and their total size.
    bool foundEnd = false;
    for (size_t i = 0, count = pInsns->size(); ((i < count) && (overwrittenSize < maxPatchSize)); ++i) {
      const auto& insn = (*pInsns)[i];

      // Assume int 3 or nop instructions are padders.
      // ** TODO Check for 2 or more NUL
      if (foundEnd && (insn.bytes[0] != 0xCC) && (insn.bytes[0] != 0x90)) {
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

      if ((bestSize < sizeof(Jmp8))   && (overwrittenSize >= sizeof(Jmp8))  ||
          (bestSize < sizeof(Jmp32))  && (overwrittenSize >= sizeof(Jmp32)) ||
          (bestSize < sizeof(JmpAbs)) && (overwrittenSize >= sizeof(JmpAbs)))
      {
        bestSize  = overwrittenSize;
        bestCount = oldCount;
      }
    }

    if (bestSize >= sizeof(Jmp32)) {
      *pOverwrittenSize = bestSize;
      pInsns->resize(bestCount);
    }
    else if (bestSize >= sizeof(Jmp8)) {
      status = Status::FailDisassemble;

      // Count how many alignment padding bytes are before the function.  If we have enough space for a jmp32 in there,
      // we can overwrite the start of the function with jmp8 to the jmp32 written in the padders.
      uint8* pReader = static_cast<uint8*>(pAddress);

      // Padder bytes are typically int 3 (0xCC), nop (0x90), or NUL.
      // ** TODO Check for 2 or more NUL
      // ** TODO Check that pReader[-sizeof(Jmp32)] is a valid executable memory address
      for (int32 i = 1; ((pReader[-i] == 0xCC) || (pReader[-i] == 0x90)); ++i) {
        if (i >= static_cast<int32>(sizeof(Jmp32))) {
          *pOverwrittenSize = bestSize;
          pInsns->resize(bestCount);
          status = Status::Ok;
          break;
        }
      }
    }
    else {
      status = Status::FailDisassemble;
    }
  }

  return status;
}

// =====================================================================================================================
// Functionally copies machine code instructions from one code memory location to another.
// Note that this function does not flush the instruction cache.
static void CopyInstructions(
  Assembler*         pWriter,
  const InsnVector&  insns,
  uint8              overwrittenSize,
  uint8              offsetLut[MaxOverwriteSize])
{
  assert((pWriter != nullptr) && (insns.empty() == false) && (offsetLut != nullptr));

  uint8*const  pBegin  = pWriter->GetNext();
  size_t  curOldOffset = 0;
  std::vector<std::pair<int32*, int32>> internalPcRel32Relocs;

  ptrdiff_t   pcRelTarget = 0;
  uintptr     target      = 0;
  ptrdiff_t   offset      = 0;
  bool        isInternal  = false;
  bool        isNear      = true;

  auto SetTarget = [&, overwrittenSize](const cs_insn& insn, ptrdiff_t pcRel32) {
    pcRelTarget = pcRel32;
    target      = static_cast<uintptr>(pcRelTarget + insn.address + insn.size);
    offset      = static_cast<ptrdiff_t>(target    - insns[0].address);
    isInternal  = (offset >= 0) && (static_cast<size_t>(offset) < overwrittenSize);
#if PATCHER_X86_64
    const auto targetOffset = static_cast<ptrdiff_t>(target - insn.address);
    isNear      = isInternal || ((targetOffset <= INT32_MAX) && (targetOffset >= INT32_MIN));
#endif
  };

  auto WritePcRel32Operand = [pWriter, &isInternal, &target, &offset, &internalPcRel32Relocs] {
    if (isInternal) {
      internalPcRel32Relocs.emplace_back(pWriter->GetNext<int32*>(), int32(offset));
    }
    pWriter->Value(isInternal ? 0 : pWriter->GetPcRelPtr<int32>(sizeof(int32), reinterpret_cast<void*>(target)));
  };

  for (size_t i = 0; i < insns.size(); ++i) {
    const auto& insn  = insns[i];
    const auto& bytes = insn.bytes;

    // Store mapping of the original instruction to the offset of the new instruction we're writing.
    offsetLut[curOldOffset] = static_cast<uint8>(PtrDelta(pWriter->GetNext(), pBegin));
    curOldOffset += insn.size;

    // Instructions which use program counter-relative operands must be changed to 32-bit or absolute form and fixed up.
    // Call pcrel32
    if (bytes[0] == 0xE8) {
      SetTarget(insn, reinterpret_cast<const Call32*>(&bytes[0])->operand);

      if (isNear) {
        pWriter->Byte(0xE8);
        WritePcRel32Operand();
      }
      else {
        pWriter->Value(CallAbs(target));
      }
    }
    // Jump pcrel8/pcrel32
    else if ((bytes[0] == 0xEB) || (bytes[0] == 0xE9)) {
      SetTarget(insn, (bytes[0] == 0xE9) ? reinterpret_cast<const Jmp32*>(&bytes[0])->operand : int8(bytes[1]));

      if (isNear) {
        pWriter->Byte(0xE9);
        WritePcRel32Operand();
      }
      else {
        pWriter->Value(JmpAbs(target));
      }
    }
    // Conditional jump pcrel8/pcrel32
    else if ((bytes[0] >= 0x70) && (bytes[0] <= 0x7F) ||
             ((bytes[0] == 0x0F) && (bytes[1] >= 0x80) && (bytes[1] <= 0x8F)))
    {
      SetTarget(insn, (bytes[0] == 0x0F) ? int32(reinterpret_cast<const Op2_4*>(&bytes[0])->operand) : int8(bytes[1]));

      if (isNear) {
        pWriter->Bytes({ 0x0F, (bytes[0] == 0x0F) ? bytes[1] : static_cast<uint8>(bytes[0] + 0x10) });
        WritePcRel32Operand();
      }
      else {
        pWriter->Value(JccAbs((bytes[0] == 0x0F) ? (bytes[1] - 0x10) : bytes[0], target));
      }
    }
    // Loop, jump if ECX == 0 pcrel8
    else if ((bytes[0] >= 0xE0) && (bytes[0] <= 0xE3)) {
      SetTarget(insn, static_cast<int8>(bytes[1]));

      if (isNear) {
        if (isInternal) {
          internalPcRel32Relocs.emplace_back(&pWriter->GetNext<Loop32*>()->ifTrue.operand, int32(offset));
        }
        pWriter->Value(Loop32(bytes[0], pWriter->GetPcRelPtr<int32>(sizeof(Loop32), reinterpret_cast<void*>(target))));
      }
      else {
        pWriter->Value(JccAbs(bytes[0], target));
      }
    }
    else {
      // Just copy instructions without PC rel operands verbatim.
      pWriter->Bytes({ &bytes[0], insn.size });
    }
  }

  // Target operands to inside of the overwritten area, which need to point to inside of our copied instructions.
  // Target could be a later instruction we hadn't copied yet at the time, so we have to fix this up as a post-process.
  for (const auto& reloc : internalPcRel32Relocs) {
    *(reloc.first) = PcRelPtr(reloc.first, 4, (pBegin + offsetLut[reloc.second]));
  }
}

// =====================================================================================================================
// Creates a trampoline to call the original code that had been overwritten by a hook. Call after FindHookPatchRegion().
static Status CreateTrampoline(
  void*             pAddress,
  Allocator*        pAllocator,
  const InsnVector& insns,
  uint8             overwrittenSize,
  void**            ppTrampoline,                          // [out] Pointer to where trampoline code (or prolog) begins.
  size_t*           pTrampolineSize,                       // [out] Size in bytes of trampoline allocation.
  size_t            prologSize                  = 0,       // [in]  Bytes to prepend for custom code.
  uint8             offsetLut[MaxOverwriteSize] = nullptr) // [out] LUT of old instruction offsets : trampoline offsets.
{
  assert((pAddress != nullptr) && (ppTrampoline != nullptr) && (pAllocator != nullptr));
  assert((prologSize % CodeAlignment) == 0);

  void*  pTrampoline = nullptr;
  size_t allocSize   = 0;

  // Allocate memory to store the trampoline.
  allocSize     = Align((prologSize + (MaxCopiedInstructionSize * insns.size()) + sizeof(JmpAbs) + CodeAlignment - 1),
                        CodeAlignment);
  pTrampoline   = pAllocator->Alloc(allocSize, CodeAlignment);
  Status status = (pTrampoline != nullptr) ? Status::Ok : Status::FailMemAlloc;

  if (status == Status::Ok) {
    uint8 localOffsetLut[MaxOverwriteSize];
    if (offsetLut == nullptr) {
      memset(&localOffsetLut[0], 0, sizeof(localOffsetLut));
      offsetLut = localOffsetLut;
    }

    // Our trampoline needs to be able to reissue instructions overwritten by the jump to it.
    Assembler writer(static_cast<uint8*>(pTrampoline) + prologSize);
    CopyInstructions(&writer, insns, overwrittenSize, offsetLut);

    // Complete the trampoline by writing a jmp instruction to the original function.
    const ptrdiff_t jmpDelta = writer.GetPcRelPtr(sizeof(Jmp32), PtrInc(pAddress, overwrittenSize));
    const bool      isFar    = IsX86_64 && ((jmpDelta > INT32_MAX) || (jmpDelta < INT32_MIN));

    isFar ? writer.Value(JmpAbs(PtrInc<uintptr>(pAddress, overwrittenSize)))
          : writer.Value(Jmp32{ 0xE9, static_cast<int32>(jmpDelta) });

    // Fill in any left over bytes with int 3 (breakpoint) padders.
    const size_t remainingSize = allocSize - PtrDelta(writer.GetNext(), pTrampoline);
    if (remainingSize > 0) {
      writer.Memset(0xCC, remainingSize);
    }
  }

  if ((status != Status::Ok) && (pTrampoline != nullptr)) {
    pAllocator->Free(pTrampoline);
    pTrampoline = nullptr;
  }

  if (status == Status::Ok) {
    *ppTrampoline    = pTrampoline;
    *pTrampolineSize = allocSize;
    FlushInstructionCache(GetCurrentProcess(), pTrampoline, allocSize);
  }

  return status;
}

// =====================================================================================================================
// Writes code for a far (absolute) jump thunk.
static Status CreateFarThunk(
  void*               pFarThunk,
  const FunctionRef&  pfnNewFunction)
{
  Status status = Status::Ok;

  if (pfnNewFunction.Functor() == nullptr) {
    *static_cast<JmpAbs*>(pFarThunk) = JmpAbs(reinterpret_cast<uintptr>(pfnNewFunction.Pfn()));

    if (sizeof(JmpAbs) < FarThunkSize) {
      // Fill padding bytes with int 3 (breakpoint).
      memset(PtrInc(pFarThunk, FarThunkSize), 0xCC, FarThunkSize - sizeof(JmpAbs));
    }
  }
  // If this thunk is for a state-bound functor, then we can inline the functor thunk instructions.
  else if (CreateFunctorThunk(pFarThunk, pfnNewFunction) == false) {
    status = Status::FailInvalidCallback;
  }

  if (status == Status::Ok) {
    FlushInstructionCache(GetCurrentProcess(), pFarThunk, FarThunkSize);
  }

  return status;
}

// =====================================================================================================================
Status PatchContext::Hook(
  TargetPtr           pAddress,
  const FunctionRef&  pfnNewFunction,
  void*               pPfnTrampoline)
{
  status_ = (status_        != Status::Ok) ? status_                     :
            (pAddress       == nullptr)    ? Status::FailInvalidPointer  :
            (pfnNewFunction == nullptr)    ? Status::FailInvalidCallback : Status::Ok;

  pAddress = MaybeFixTargetPtr(pAddress);

  const void* pHookFunction   = pfnNewFunction;
  void*       pTrampoline     = nullptr;
  void*       pFarThunk       = nullptr;
  uint8       overwrittenSize = 0;
  size_t      trampolineSize  = 0;
  InsnVector  insns;

  if (status_ == Status::Ok) {
    // Destroy any existing trampoline or functor.
    // ** TODO Be able to handle stacking multiple hooks; for now use of multiple PatchContexts can mostly do that.
    Revert(pAddress);
  }

  if (status_ == Status::Ok) {
    status_ = FindHookPatchRegion(pAddress, &overwrittenSize, &insns);
  }

  const auto jmpDelta      = PcRelPtr<ptrdiff_t>(pAddress, sizeof(Jmp32), pfnNewFunction);
  const bool isFar         = IsFarDisplacement(jmpDelta);
  const bool needsFarThunk = isFar && (overwrittenSize < sizeof(JmpAbs));

  if (status_ == Status::Ok) {
    // Generate the trampoline to the original code if requested, and the far jump thunk if needed.
    if (pPfnTrampoline != nullptr) {
      status_ = CreateTrampoline(
        pAddress, pAllocator_, insns, overwrittenSize, &pTrampoline, &trampolineSize, needsFarThunk ? FarThunkSize : 0);

      if (needsFarThunk && (status_ == Status::Ok)) {
        pFarThunk   = pTrampoline;
        pTrampoline = PtrInc(pFarThunk, FarThunkSize);
      }
    }
    else if (needsFarThunk) {
      pFarThunk      = pAllocator_->Alloc(FarThunkSize, CodeAlignment);
      trampolineSize = FarThunkSize;

      if (pFarThunk == nullptr) {
        status_ = Status::FailMemAlloc;
      }
    }
  }

  if (needsFarThunk && (status_ == Status::Ok)) {
    // Write the far jump thunk code.
    status_ = CreateFarThunk(pFarThunk, pfnNewFunction);
  }

  if (status_ == Status::Ok) {
    uint8 buffer[MaxOverwriteSize];
    Assembler writer(buffer);

    void* pPatchAddr = pAddress;

    if (isFar && (overwrittenSize >= sizeof(JmpAbs))) {
      // There is enough space to write a JmpAbs at pAddress.
      writer.Value(JmpAbs(reinterpret_cast<uintptr>(pHookFunction)));
    }
    else if (overwrittenSize >= sizeof(Jmp32)) {
      // There is enough space to write a Jmp32 at pAddress.
      writer.Value(Jmp32{ 0xE9, PcRelPtr(pAddress, sizeof(Jmp32), pHookFunction) });
    }
    else if (overwrittenSize >= sizeof(Jmp8)) {
      // There isn't enough space for a Jmp32 at pAddress, but there is in the padding bytes preceding it, and there is
      // enough room for a Jmp8 referencing the Jmp32.
      pPatchAddr       = PtrDec(pAddress, sizeof(Jmp32));
      overwrittenSize += sizeof(Jmp32);
      writer.Value(Jmp32{ 0xE9, static_cast<int32>(PtrDelta(pHookFunction, pAddress)) })
            .Value(Jmp8{  0xEB, writer.GetPcRelPtr<int8>(sizeof(Jmp8), PtrDec(writer.GetNext(), sizeof(Jmp32))) });
    }
    else {
      // Not enough space to write a jump to our hook function.
      status_ = Status::FailInstallHook;
    }

    if ((status_ == Status::Ok) && (writer.GetPosition() < overwrittenSize)) {
      // Write no-ops if an instruction is partially overwritten.
      writer.Memset(0x90, overwrittenSize - writer.GetPosition());
    }

    if ((Memcpy(pPatchAddr, &buffer[0], overwrittenSize) == Status::Ok) && (pPatchAddr != pAddress)) {
      // Fix up the lookup address key in the historyAt_ map so we can still revert by the user-supplied address.
      auto it = historyAt_.find(pPatchAddr);
      historyAt_[pAddress] = it->second;
      historyAt_.erase(it);
    }
  }

  if (status_ == Status::Ok) {
    PatchInfo& entry = *historyAt_[pAddress];

    // Add trampoline/functor info to the history tracker entry for this patch so we can clean it up later.
    if ((pFarThunk != nullptr) || (pTrampoline != nullptr)) {
      entry.trackedAllocs.Emplace(((pFarThunk != nullptr) ? pFarThunk : pTrampoline), trampolineSize);
    }
    entry.pFunctorObj     = pfnNewFunction.Functor();
    entry.pfnFunctorThunk =
      ((needsFarThunk == false) && (pfnNewFunction.Functor() != nullptr)) ? pfnNewFunction : nullptr;

    if (pPfnTrampoline != nullptr) {
      *static_cast<void**>(pPfnTrampoline) = pTrampoline;
    }
  }
  else if ((pTrampoline != nullptr) || (pFarThunk != nullptr)) {
    pAllocator_->Free((pFarThunk != nullptr) ? pFarThunk : pTrampoline);
  }

  return status_;
}

// =====================================================================================================================
Status PatchContext::HookCall(
  TargetPtr           pAddress,
  const FunctionRef&  pfnNewFunction,
  void*               pPfnOriginal)
{
  status_ = (status_        != Status::Ok) ? status_                     :
            (pAddress       == nullptr)    ? Status::FailInvalidPointer  :
            (pfnNewFunction == nullptr)    ? Status::FailInvalidCallback : Status::Ok;

  pAddress = MaybeFixTargetPtr(pAddress);

  if (status_ == Status::Ok) {
    // Destroy any existing trampoline or functor.
    // ** TODO Be able to handle stacking multiple hooks; for now use of multiple PatchContexts can mostly do that.
    Revert(pAddress);
  }

  auto*const  pInsn         = static_cast<uint8*>(pAddress);
  const void* pHookFunction = pfnNewFunction;
  void*       pfnOriginal   = nullptr;
  void*       pFarThunk     = nullptr;

  const auto callDelta = PcRelPtr<ptrdiff_t>(pAddress, sizeof(Call32), pfnNewFunction);
  const bool isFar     = IsFarDisplacement(callDelta);

  // Create a far jump thunk if needed.
  if (isFar && (status_ == Status::Ok)) {
    pFarThunk = pAllocator_->Alloc(FarThunkSize, CodeAlignment);

    if (pFarThunk != nullptr) {
      status_ = CreateFarThunk(pFarThunk, pfnNewFunction);
      pHookFunction = pFarThunk;
    }
    else {
      status_ = Status::FailMemAlloc;
    }
  }

  if (status_ == Status::Ok) {
    if (pInsn[0] == 0xE8) {
      // Call pcrel32
      pfnOriginal = PtrInc(pAddress, sizeof(Call32) + reinterpret_cast<ptrdiff_t&>(pInsn[1]));
      Write(pAddress,  Call32{ 0xE8, PcRelPtr(pAddress, sizeof(Call32), pHookFunction) });
    }
    else if ((pInsn[0] == 0xFF) && (((pInsn[1] >= 0x10) && (pInsn[1] <= 0x17)) ||
                                    ((pInsn[1] >= 0x50) && (pInsn[1] <= 0x57)) ||
                                    ((pInsn[1] >= 0x90) && (pInsn[1] <= 0x97))))
    {
      // Call r32/r64/m32
      const auto insns = g_disasm.Disassemble(pAddress, 1);
      status_ = (insns.size() != 0) ? g_disasm.GetLastError() : Status::FailDisassemble;

      if (status_ == Status::Ok) {
        const size_t insnSize = insns.empty() ? 0 : insns[0].size;

        // If call m32, get its destination address.
        if (IsX86_32 && (insnSize == 6) && (pInsn[1] == 0x15)) {
          pfnOriginal = *reinterpret_cast<void**&>(pInsn[2]);
        }
        else if (IsX86_64 && (insnSize == 7) && (pInsn[1] == 0x14) && (pInsn[2] == 0x25)) {
          pfnOriginal = reinterpret_cast<void*>(static_cast<uintptr>(*reinterpret_cast<uint32*&>(pInsn[3])));
        }

        if (insnSize >= sizeof(Call32)) {
          PATCHER_PACK_STRUCT
          struct {
            Call32  call;
            uint8   pad[MaxInstructionSize - sizeof(Call32)];
          } code;
          PATCHER_END_PACK_STRUCT

          code.call = { 0xE8, PcRelPtr(pAddress, sizeof(Call32), pHookFunction) };
          memset(&code.pad[0], 0x90, sizeof(code.pad));
          Memcpy(pAddress, &code, insnSize);
        }
        else {
          // ** TODO Support this case using trampolines.
          status_ = Status::FailInstallHook;
        }
      }
    }
    else {
      // Invalid instruction for hooking.
      status_ = Status::FailInstallHook;
    }
  }

  if ((status_ == Status::Ok) && (pPfnOriginal != nullptr)) {
    // ** TODO Possibly implement this for call r32/r64 variants, for now returns nullptr in those cases
    *static_cast<void**>(pPfnOriginal) = pfnOriginal;
  }

  if (status_ == Status::Ok) {
    // Add functor and far thunk info to the history tracker entry for this patch so we can clean it up later.
    auto& entry = *historyAt_[pAddress];
    if (isFar) {
      entry.trackedAllocs.Emplace(pFarThunk, FarThunkSize);
    }
    entry.pFunctorObj      = pfnNewFunction.Functor();
    entry.pfnFunctorThunk  = ((isFar == false) && (pfnNewFunction.Functor() != nullptr)) ? pfnNewFunction : nullptr;
  }
  else if (pFarThunk != nullptr) {
    pAllocator_->Free(pFarThunk);
  }

  return status_;
}

// =====================================================================================================================
// Helper function to generate low-level hook trampoline code.
static size_t CreateLowLevelHookTrampoline(
  void*               pLowLevelHook,
  Span<RegisterInfo>  registers,
  const void*         pAddress,
  const FunctionRef&  pfnHookCb,
  ptrdiff_t           moduleRelocDelta,
  const uint8         (&offsetLut)[MaxOverwriteSize],
  uint8               overwrittenSize,
  LowLevelHookInfo    settings)
{
#if PATCHER_X86_32
  static constexpr Register VolatileRegisters[] = { Register::Ecx, Register::Edx, Register::Eax };
  static constexpr Register ArgRegisters[]      = { Register::Count };
#elif PATCHER_X86_64
  static constexpr Register VolatileRegisters[] = {
# if PATCHER_UNIX_ABI
    Register::Rdi, Register::Rsi,
# endif
    Register::R8,  Register::R9,  Register::R10, Register::R11, Register::Rcx, Register::Rdx, Register::Rax
  };
# if PATCHER_MS_ABI
  static constexpr Register ArgRegisters[]      = { Register::Rcx, Register::Rdx, Register::R8, Register::R9 };
# elif PATCHER_UNIX_ABI
  static constexpr Register ArgRegisters[]      =
    { Register::Rdi, Register::Rsi, Register::Rdx, Register::Rcx, Register::R8, Register::R9 };
# endif
#endif
  static constexpr Register ReturnRegister      = IF_X86_32(Register::Eax)    IF_X86_64(Register::Rax);
  static constexpr Register StackRegister       = IF_X86_32(Register::Esp)    IF_X86_64(Register::Rsp);
  static constexpr Register FlagsRegister       = IF_X86_32(Register::Eflags) IF_X86_64(Register::Rflags);
  static constexpr uint8    StackAlignment      = PATCHER_DEFAULT_STACK_ALIGNMENT;
  static constexpr bool     UseRedZone          = (PATCHER_STACK_RED_ZONE_SIZE >= RegisterSize);

  // Fix user-provided options to ignore redundant flags and sanitize inputs.
  if (settings.noCustomReturnAddr) {
    settings.noBaseRelocReturn   = 0;
    settings.noShortReturnAddr   = 0;
    settings.noNullReturnDefault = 0;
  }
  if (StackAlignment <= RegisterSize) {
    settings.noAlignStackPtr = 1;
  }
  settings.reserveStackSize = Align(settings.reserveStackSize, RegisterSize);

  uint32 numByRef = 0;
  for (const auto& reg : registers) {
    if (reg.byReference) {
      ++numByRef;
    }
  }

  std::vector<RegisterInfo> stackRegisters;  // Registers, in order they are pushed to the stack in (RTL).
  stackRegisters.reserve(registers.Length() + ArrayLen(VolatileRegisters) + numByRef + 2);  // +2 for ESP and Eflags

  uint32 regValueIndexData[uint32(Register::Count)]; // Stack slot indexes of register values (UINT_MAX if not present).
  for (uint32 i = 0; i < uint32(Register::Count); regValueIndexData[i++] = UINT_MAX);
  const Span<uint32> regValueIndex(regValueIndexData);

  auto AddRegisterToStack = [&stackRegisters, &regValueIndexData, &regValueIndex](RegisterInfo reg) {
    if ((reg.byReference == false) && (reg.offset == 0) && (regValueIndex[reg.type] == UINT_MAX)) {
      regValueIndexData[uint32(reg.type)] = uint32(stackRegisters.size());
    }
    stackRegisters.push_back(reg);
  };

  // Registers that the ABI considers volatile between function calls must be pushed to the stack unconditionally.
  // Find which ones haven't been explicitly requested, and have them be pushed to the stack before everything else.
  uint32 requestedRegMask   = 0;
  uint32 requestedByRefMask = 0;
  if (registers.IsEmpty() == false) {
    for (uint32 i = 0; i < registers.Length(); ++i) {
      assert(registers[i].type < Register::Count);
      if (registers[i].offset == 0) {
        requestedRegMask   |= (1u << uint32(registers[i].type));
        requestedByRefMask |= registers[i].byReference ? (1u << uint32(registers[i].type)) : 0;
      }
    }
  }
  auto IsRegisterRequested = [&requestedRegMask, &requestedByRefMask](Register reg, bool byRef = false)
    { return BitFlagTest(byRef ? requestedByRefMask : requestedRegMask, 1u << uint32(reg)); };

  if (settings.noAlignStackPtr == false) {
    // If we are aligning the stack pointer, then the original stack register address is the first thing we must push.
    AddRegisterToStack({ StackRegister });
  }
  if ((settings.noRestoreFlagsReg == false) &&
      ((IsRegisterRequested(FlagsRegister) == false) || (settings.noAlignStackPtr == false)))
  {
    AddRegisterToStack({ FlagsRegister });
  }
  for (const Register reg : VolatileRegisters) {
    if (IsRegisterRequested(reg) == false) {
      AddRegisterToStack({ reg });
    }
  }

  if (registers.IsEmpty() == false) {
    // Registers by reference must be pushed prior to function args;  references to them are pushed alongside the args.
    for (auto reg : registers) {
      if (reg.byReference && (regValueIndex[reg.type] == UINT_MAX)) {
        reg.byReference = false;
        AddRegisterToStack(reg);
      }
    }

    // Push the function args the user-provided callback will actually see now.
    for (size_t i = registers.Length(); i > 0; AddRegisterToStack(registers[--i]));

    if (settings.argsAsStructPtr) {
      // Pushing ESP last is equivalent of pushing a pointer to everything before it on the stack.
      AddRegisterToStack({ StackRegister });
    }
  }

  // Write the low-level hook trampoline code.
  Assembler writer(pLowLevelHook);

  const bool isFunctor = (pfnHookCb.Functor() != nullptr);
  const bool saveFlags = (settings.noRestoreFlagsReg == false);

  // The x64 calling convention passes the first 4 arguments via registers in MS ABI, or the first 6 in Unix ABI.
  const size_t numPassedViaRegisters = (IsX86_32 || isFunctor) ? 0 :
    Min((settings.argsAsStructPtr ? 1 : registers.Length()), ArrayLen(ArgRegisters));

  // Scratch space reserved on the stack first that can be used to store temporary data, which is mainly used to avoid
  // issues where we could otherwise reference invalidated stack memory.
  static constexpr uint8 ScratchSpaceSize = uint8(RegisterSize * 2);
  const bool   noNeedScratchSpace = (settings.noAlignStackPtr && settings.noCustomReturnAddr &&
    ((IsRegisterRequested(StackRegister) == false) || (regValueIndex[StackRegister] == 0)));
  const uint32 totalReserveSize   = settings.reserveStackSize + (noNeedScratchSpace ? 0 : ScratchSpaceSize);

  // Prolog begins here.
  writer.ByteIf(settings.debugBreakpoint, 0xCC);  // int 3

  if (settings.noAlignStackPtr == false) {
    // Ensure the stack address upon reaching the upcoming call instruction is aligned to ABI requirements.
    // This always pushes the original stack pointer (and flags register if needed) to the stack after aligning.
    // Generating this code isn't necessary if stack alignment <= register size (i.e. MSVC x86-32).
    const size_t totalStackSize = RegisterSize *
      (stackRegisters.size()
        - numPassedViaRegisters                     // Passed via registers
        + ((IsX86_64 && IsMsAbi) ? 4 : 0)           // Shadow space (MS x86-64 ABI)
        + (isFunctor ? InvokeFunctorNumArgs : 0));  // InvokeFunctor() args

    static constexpr uint8 StackAlignMask = uint8(-int8(StackAlignment));
    const int32 eaxOffset    = -int32(settings.reserveStackSize + (RegisterSize * 1));
    const int32 flagsOffset  = -int32(settings.reserveStackSize + (RegisterSize * 2));
    const uint8 alignDelta   = uint8(-int8(
      (totalStackSize & (StackAlignment - 1)) - StackAlignment)) & (StackAlignment - 1);
    const uint8 usedScratch  = uint8(RegisterSize * (saveFlags ? 2 : 1));  // For push eax (+ pushf)
    const uint8 remScratch   =
      uint8((ScratchSpaceSize > usedScratch) ? (ScratchSpaceSize - usedScratch) : 0);
    const bool  restoreFlags = saveFlags && IsRegisterRequested(FlagsRegister);

    if (settings.reserveStackSize != 0) {
      // Reserve user-requested stack space.
      writer.Add(StackRegister, -int32(settings.reserveStackSize));
    }

    writer
      .Push(ReturnRegister)                                             // push eax      (Save EAX to scratch[0])
      .ByteIf(saveFlags, 0x9C)                                          // pushf         (Save Eflags to scratch[1])
      .BytesIf(remScratch, { IF_X86_64(0x48,) 0x83, 0xEC, remScratch }) // sub  esp, i8  (Reserve remaining scratch)
      .Bytes({ IF_X86_64(0x48,) 0x89, 0xE0 })                           // mov  eax, esp
      .BytesIf(restoreFlags, { 0xFF, 0x74, 0x24, remScratch })          // push dword ptr [esp + i8]  (Fast copy Eflags)
      .Bytes({ IF_X86_64(0x48,) 0x83, 0xE0, StackAlignMask,             // and  eax, -16              (Calc aligned ESP)
               IF_X86_64(0x48,) 0x83, 0xE8, alignDelta })               // sub  eax, alignDelta
      .ByteIf(restoreFlags, 0x9D)                                       // popf                       (Restore Eflags)
      .Bytes({ IF_X86_64(0x48,) 0x94 })                                 // xchg eax, esp              (Align ESP)
      .Add(ReturnRegister, totalReserveSize)                            // lea  eax, [eax + N]
      .Push(ReturnRegister);                                            // push eax                       (Save old ESP)

    if (totalReserveSize == int8(totalReserveSize)) {
      writer.BytesIf(saveFlags, { 0xFF, 0x70, uint8(flagsOffset) })     // push dword ptr [eax + N]       (Save Eflags)
            .Bytes({ IF_X86_64(0x48,) 0x8B, 0x40, uint8(eaxOffset) });  // mov  eax, dword ptr [eax + N]  (Restore EAX)
    }
    else {
      if (saveFlags) { writer.Op<2, int32>({ { 0xFF, 0xB0 }, flagsOffset }); }
      writer.Op<IsX86_64 ? 3 : 2, int32>({ { IF_X86_64(0x48,) 0x8B, 0x80 }, eaxOffset });
    }
  }
  else {
    // Reserve user-requested stack space and our scratch space.
    writer.Add(StackRegister, -int32(totalReserveSize));  // lea esp, [esp - i8]
  }

  // Pushes the current stack pointer, possibly adjusted by some offset, to the top of the stack.  Iff we generated the
  // stack align code above, passing fromOrigin = true pushes the old pre-aligned stack pointer instead of current SP.
  Register spareRegister = Register::Count;
  auto PushAdjustedStackReg = [&](size_t index, uint32 addend, bool fromOrigin = false) {
    assert((fromOrigin == false) || (settings.noAlignStackPtr == false));  // fromOrigin requires aligned stack mode.
    addend += (fromOrigin == false) ? uint32(RegisterSize * index) : 0;

    if ((addend == 0) && (fromOrigin == false)) {
      writer.Push(StackRegister);  // push esp
    }
    else {
      // See if there's an already-stored register we can use.  This assumes that index only monotonically increases.
      if (spareRegister == Register::Count) {
        for (auto it = stackRegisters.begin(); it != (stackRegisters.begin() + index); ++it) {
          const Register reg = it->type;

          if (reg < Register::GprLast) {
            // Ensure this register does not need to be stored by value again later before we try to clobber it.
            const auto futureUse = std::find_if(it + 1, stackRegisters.end(), [reg](const RegisterInfo& x)
              { return (x.type == reg) && (x.byReference == false); });
            if (futureUse == stackRegisters.end()) {
              spareRegister = reg;
              break;
            }
          }
        }
      }

      // Offset to origin ESP, i.e. the first thing pushed to the stack in aligned-stack mode.  Since we can't
      // statically calculate the stack alignment offset in that mode, we need to reference the copy of the old value.
      const int32    originOffset    = int32(RegisterSize * (index - ((spareRegister != Register::Count) ? 1 : -1)));
      const Register scratchRegister = (spareRegister != Register::Count) ? spareRegister : ReturnRegister;

      if (spareRegister == Register::Count) {
        // There is no available register, so we need to save and later restore a scratch register.
        writer.Add(StackRegister, -int32(RegisterSize))  // lea  esp, [esp - 4]  (Reserve space)
              .Push(scratchRegister);                    // push eax
        addend += (fromOrigin == false) ? (RegisterSize * 2) : 0;
      }

      // If fromOrigin, push (*(esp + originOffset) + addend).  Otherwise, push (esp + addend).
      fromOrigin ? writer.LoadStackValue(scratchRegister, originOffset)      // mov  reg, [esp + originOffset]
                         .Add(scratchRegister, int32(addend))                // lea  reg, [reg + addend]
                 : writer.LoadStackAddress(scratchRegister, int32(addend));  // lea  reg, [esp + addend]
      (spareRegister != Register::Count) ? writer.Push(scratchRegister)                           // push reg
                                         : writer.StoreStackValue(scratchRegister, RegisterSize)  // mov  [esp + 4], reg
                                                 .Pop(scratchRegister);                           // pop  reg
    }
  };

  // Push required registers to the stack in RTL order, per the cdecl calling convention.
  // In stack align mode, the SP is assumed to have been pushed first already (followed by flags if needed).
  const size_t numAlreadyPushed    = (settings.noAlignStackPtr ? 0 : (settings.noRestoreFlagsReg ? 1 : 2));
  uint8        numReferencesPushed = 0;
  for (auto it = stackRegisters.begin() + numAlreadyPushed; it != stackRegisters.end(); ++it) {
    const Register reg   = it->type;
    const size_t   index = (it - stackRegisters.begin());
    if (it->byReference) {
      // Register by reference.
      PushAdjustedStackReg(index, uint32(RegisterSize * -(int32(regValueIndex[reg]) + 1)), false);
    }
    else if (reg == StackRegister) {
      settings.noAlignStackPtr ? PushAdjustedStackReg(index, it->offset + totalReserveSize)
                               : PushAdjustedStackReg(index, it->offset, true);
    }
    else {
      writer.Push(reg);
    }
  }

  // Move arguments into registers as required by the ABI.
  // ** TODO x64 Moving from register to register would be more optimal, but then we'd have to deal with potential
  //         dependencies (if any arg registers e.g. RCX are requested), and reorder the movs or fall back to
  //         xchg/push+pop as needed.
  for (size_t i = 0; i < numPassedViaRegisters; writer.Pop(ArgRegisters[i++]), stackRegisters.pop_back());

  uint8*     pSkipCase1Offset = nullptr;
  void*const pTrampolineToOld = PtrInc(pLowLevelHook, MaxLowLevelHookSize);

  // Write the call instruction to our hook callback function.
  // If return value == nullptr, or custom return destinations aren't allowed, we can take a simpler path.
  if (isFunctor) {
    // We need to push the first 2 args to FunctionRef::InvokeFunctor().
    IsX86_32 ? writer.Bytes({ 0x6A, 0x00 })                                            // push   0  (pPrevReturnAddr)
                     .Op(Op1_4{ 0x68, uint32(uintptr(pfnHookCb.Functor().get())) })    // push   pFunctor
             : writer.Bytes({ 0x48, 0x31, 0xC0 })                                      // xor    rax, rax
                     .Push(ReturnRegister)                                             // push   rax
                     .Op(Op2_8{ { 0x48, 0xB8 }, uintptr(pfnHookCb.Functor().get()) })  // movabs rax, pFunctor
                     .Push(ReturnRegister);                                            // push   rax
  }

  // MS x64 ABI expects 32 bytes of shadow space be allocated on the stack just before the call.
  writer.BytesIf((IsX86_64 && IsMsAbi), { 0x48, 0x83, 0xEC, uint8(RegisterSize * 4) });        // sub    rsp, 32

  {
    const void* pHookFunction = isFunctor ? pfnHookCb.InvokerPfnTable().pfnInvokeWithPad[0] : pfnHookCb.Pfn();
    const auto  callDelta     = writer.GetPcRelPtr<ptrdiff_t>(sizeof(Call32), pHookFunction);
    IsFarDisplacement(callDelta) ? writer.Op(Op2_8{ { 0x48, 0xB8 }, uintptr(pHookFunction) })  // movabs rax, pfnHookCb
                                         .Bytes({ 0xFF, 0xD0 })                                // call   rax
                                 : writer.Value(Call32{ 0xE8, int32(callDelta) });             // call   pfnHookCb
  }

  // Epilog begins here.
  // Pop the shadow space if MS x64 ABI, and then the InvokeFunctor() args if we passed them.
  if (IsX86_64 && IsMsAbi) {
    writer.PopNil(4);                                                                          // lea    rsp, [rsp + 32]
  }
  if (isFunctor) {
    writer.PopNil(InvokeFunctorNumArgs);                                                       // lea    esp, [esp + 8]
  }

  if ((settings.noCustomReturnAddr || settings.noNullReturnDefault) == false) {
    writer.Bytes({ IF_X86_64(0x48,) 0x85, 0xC0,  // test eax, eax  (Test if returned address is nullptr)
                   0x75, 0x00 });                // jnz  short i8  (Skip to case 2 if non-nullptr)
    pSkipCase1Offset = (writer.GetNext() - 1);   // Fill the skip to case 2 jump offset later when we know the size.
  }

  if (settings.noNullReturnDefault == false) {
    // Case 1: Return to default address (hook function returned nullptr, or custom returns are disabled)
    const bool lateRestoreStack = (IsRegisterRequested(StackRegister) &&
      (regValueIndex[StackRegister] != 0) && (regValueIndex[StackRegister] != UINT_MAX));

    // Restore register values from the stack.  We must take care not to clobber flags at this point.
    for (auto it = stackRegisters.rbegin(); it != stackRegisters.rend(); ++it) {
      const Register reg          = it->type;
      const size_t   index        = stackRegisters.size() - (it - stackRegisters.rbegin()) - 1;
      const bool     needsRestore = (it->byReference == false) && (index == regValueIndex[reg]);
      if (needsRestore && (reg == StackRegister) && lateRestoreStack) {
        // If this is the stack register, pop this arg to the near end of the scratch space.
        const int32 offset       = int32(RegisterSize * index);
        const bool  offsetIs8Bit = (offset == int8(offset));
        writer.Bytes({ 0x8F, uint8(0x44 + (offsetIs8Bit ? 0 : 0x40)), 0x24 });  // pop dword ptr [esp + offset]
        offsetIs8Bit ? writer.Value(int8(offset)) : writer.Value(offset);
      }
      else if (needsRestore) {
        writer.Pop(reg);
      }
      else {
        // Skip this arg.
        writer.PopNil();
      }
    }

    if (lateRestoreStack) {
      writer.Pop(StackRegister);                       // pop esp              (Restore ESP)
    }
    else if (regValueIndex[StackRegister] == UINT_MAX) {
      writer.PopNil(totalReserveSize / RegisterSize);  // lea esp, [esp + i8]  (Pop scratch space and user reserve)
    }

    // If there's a user-specified default return address, relocate and use that;  otherwise, return to original code.
    void* pDefaultReturnAddr = (settings.pDefaultReturnAddr == nullptr) ? pTrampolineToOld :
      PtrInc(settings.pDefaultReturnAddr, (settings.pDefaultReturnAddr.ShouldRelocate() ? moduleRelocDelta : 0));

    if ((pDefaultReturnAddr >= pAddress) && (pDefaultReturnAddr < PtrInc(pAddress, overwrittenSize))) {
      pDefaultReturnAddr = PtrInc(pTrampolineToOld, offsetLut[PtrDelta(pDefaultReturnAddr, pAddress)]);
    }

    // Jump to the default return address.
    const auto jmpDelta = writer.GetPcRelPtr<ptrdiff_t>(sizeof(Jmp32), pDefaultReturnAddr);

    IsFarDisplacement(jmpDelta) ? writer.Value(JmpAbs(uintptr(pDefaultReturnAddr)))
                                : writer.Value(Jmp32{ 0xE9, int32(jmpDelta) });      // jmp pDefaultReturnAddr
  }

  if (settings.noCustomReturnAddr == false) {
    if (pSkipCase1Offset != nullptr) {
      // Write the skip branch jmp offset now that we know the end of this branch.
      *pSkipCase1Offset = uint8(PtrDelta(writer.GetNext(), pSkipCase1Offset) - 1);
    }

    // Case 2: Return to custom destination
    if ((settings.noBaseRelocReturn == false) && (moduleRelocDelta != 0)) {
      IsX86_32 ? writer.Op(Op1_4{ 0x05,           uint32(moduleRelocDelta) })  // add    eax, u32 (Relocate return addr)
               : writer.Op(Op2_8{ { 0x48, 0xB9 }, uint64(moduleRelocDelta) })  // movabs rcx, u64
                       .Bytes({ 0x48, 0x01, 0xC8 });                           // add    rax, rcx
    }

    // If the destination is within the overwritten area, relocate it into the trampoline instead to execute the
    // intended code path.
    PATCHER_PACK_STRUCT
    struct RelocateIntoTrampolineCodeChunk {
#if PATCHER_X86_32
      // Test if the destination is within the overwritten area.
      Op1_4  testAfterOverwrite  = { 0x3D, };                     // cmp eax, u32
      Jmp8   skipBranch1         = { 0x73, sizeof(branch1) };     // jae short i8

      struct {
        Op1_4  testBeforeOverwrite = { 0x3D, };                   // cmp eax, u32
        Jmp8   skipBranch1A        = { 0x72, sizeof(branch1A) };  // jb  short i8

        struct { // Relocate destination into the trampoline to the original function.
          Op1_4  subtractOldAddress  = { 0x2D, };                 // sub eax, u32
          Op2_4  offsetTableLookup   = { { 0x8A, 0x80 }, };       // mov al, [u32 + eax]
          Op1_4  addTrampolineToOld  = { 0x05, };                 // add eax, u32
        } branch1A{};
      } branch1{};
#elif PATCHER_X86_64
      Op2_8  testAfterOverwrite     = { { 0x48, 0xB9 },  };          // movabs rcx, u64
      uint8  doCompare[3]           = { 0x48, 0x39, 0xC8 };          // cmp    rax, rcx
      Jmp8   skipBranch1            = { 0x73, sizeof(branch1) };     // jae    short i8

      struct {
        Op2_8  testBeforeOverwrite    = { { 0x48, 0xB9 },  };        // movabs rcx, u64
        uint8  doCompare[3]           = { 0x48, 0x39, 0xC8 };        // cmp    rax, rcx
        Jmp8   skipBranch1A           = { 0x72, sizeof(branch1A) };  // jb     short i8

        struct { // Relocate destination into the trampoline to the original function.
          uint8  subtractOldAddress[3]  = { 0x48, 0x29, 0xC8 };      // sub    rax, rcx
          Op2_8  offsetTableLookup      = { { 0x48, 0xB9 },  };      // movabs rcx, u64
          uint8  doLookup[3]            = { 0x8A, 0x04, 0x08 };      // mov    al, [rax + rcx]
          Op2_8  addTrampolineToOld     = { { 0x48, 0xB9 },  };      // movabs rcx, u64
          uint8  doAdd[3]               = { 0x48, 0x01, 0xC8 };      // add    rax, rcx
        } branch1A{};
      } branch1{};
#endif
    } static constexpr RelocateIntoTrampolineCodeChunkImage;
    PATCHER_END_PACK_STRUCT

    auto*const pRelocateCode = writer.GetNext<RelocateIntoTrampolineCodeChunk*>();

    if (settings.noShortReturnAddr == false) {
      writer.Value(RelocateIntoTrampolineCodeChunkImage);
      pRelocateCode->testAfterOverwrite.operand                            = PtrInc<uintptr>(pAddress, overwrittenSize);
      pRelocateCode->branch1.testBeforeOverwrite.operand                   = reinterpret_cast<uintptr>(pAddress);
      IF_X86_32(pRelocateCode->branch1.branch1A.subtractOldAddress.operand = reinterpret_cast<uintptr>(pAddress));
      // We will defer initializing the offset LUT lookup operand until we know where the LUT will be placed.
      pRelocateCode->branch1.branch1A.addTrampolineToOld.operand = reinterpret_cast<uintptr>(pTrampolineToOld);
    }

    const bool restoreStackPtr = (regValueIndex[StackRegister] != UINT_MAX) &&
      (IsRegisterRequested(StackRegister, true) || (settings.noAlignStackPtr == false));
    if (restoreStackPtr) {
      // If we're restoring the stack pointer: save the return address to either scratch[0], or if it's been changed, to
      // just below what the SP will be; and save the new SP (with space reserved for return address) to the near end of
      // scratch, or in-place if it's the last arg to pop.
      static constexpr auto ScratchRegister = IF_X86_32(Register::Ecx) IF_X86_64(Register::Rcx);
      const int32 stackValOffset = int32(RegisterSize * (stackRegisters.size() - regValueIndex[StackRegister] - 1));
      const int32 scratchOffset  =
        (regValueIndex[StackRegister] == 0) ? stackValOffset : int32(RegisterSize * stackRegisters.size());

      writer.LoadStackValue(ScratchRegister, stackValOffset);     // mov ecx, dword ptr [esp + stackValOffset] (Load SP)
      if (UseRedZone) {
        writer.Bytes({ IF_X86_64(0x48,) 0x89, 0x41, uint8(-int8(RegisterSize)) });
        if (regValueIndex[StackRegister] != 0) {                  // mov dword ptr [ecx - 4], eax  (Save return address)
          writer.StoreStackValue(ScratchRegister, scratchOffset); // mov dword ptr [esp + scratchOffset], ecx  (Save SP)
        }
      }
      else {
        writer.Add(ScratchRegister, -int32(RegisterSize))         // lea ecx, [ecx - 4]        (Reserve space)
              .Bytes({ IF_X86_64(0x48,) 0x89, 0x01 })             // mov dword ptr [ecx], eax  (Save return address)
              .StoreStackValue(ScratchRegister, scratchOffset);   // mov dword ptr [esp + scratchOffset], ecx  (Save SP)
      }
    }
    else {
      // Save the return address to scratch[0].
      const int32 scratchOffset = int32((RegisterSize * (stackRegisters.size() - 1)) + totalReserveSize);
      writer.StoreStackValue(ReturnRegister, scratchOffset);  // mov dword ptr [esp + scratchOffset], eax
    }

    // Restore register values from the stack.  We must take care not to clobber flags at this point.
    for (auto it = stackRegisters.rbegin(); it != stackRegisters.rend(); ++it) {
      const Register reg   = it->type;
      const size_t   index = stackRegisters.size() - (it - stackRegisters.rbegin()) - 1;
      if (it->byReference) {
        // Skip arg references; we only care about the actual values they point to further up the stack.
        writer.PopNil();
      }
      else if (reg == StackRegister) {
        // Stack register is special cased.
        if ((regValueIndex[StackRegister] != 0) || (index != 0)) {
          writer.PopNil();
        }
      }
      else {
        writer.Pop(reg);
      }
    }

    // Finish cleanup and jump to the address requested by the callback.
    if (UseRedZone && IsMsAbi) {
      // The first instruction at the start of the cache line is more likely to be executed just before a context
      // switch.  By ensuring the jmp instruction is at the start of the cache line, we may reduce (but not eliminate!)
      // the chance that Windows preempts us in between the pop and the jmp.
      void*const pJmp =
        PtrInc(writer.GetNext(), restoreStackPtr ? 1 : ((IsX86_64 ? 4 : 3) + ((totalReserveSize > INT8_MAX) ? 4 : 1)));
      writer.Nop(PtrDelta(PtrAlign(pJmp, CodeAlignment), pJmp));
    }

    restoreStackPtr ? writer.Pop(StackRegister)                                  // pop esp            (Restore ESP, or)
      : writer.PopNil((totalReserveSize / RegisterSize) - (UseRedZone ? 0 : 1)); // lea esp, [esp+i8]  (Pop scratch)

    // If the stack red zone is safe to use, then we can avoid a RSB branch misprediction by using jmp instead of retn.
    UseRedZone ? writer.Bytes({ 0xFF, 0x64, 0x24, uint8(-int8(RegisterSize)) })  // jmp dword ptr [esp-4]  (Jump)
               : writer.Byte(0xC3);                                              // retn                   (Return)

    if (settings.noShortReturnAddr == false) {
      // Initialize the offset LUT lookup instruction we had deferred, now that we know where we're copying the LUT to.
      pRelocateCode->branch1.branch1A.offsetTableLookup.operand = writer.GetNext<uintptr>();
      // Copy the offset lookup table.
      writer.Bytes({ &offsetLut[0], overwrittenSize });
    }
  }

  const size_t size = writer.GetPosition();
  assert(size <= MaxLowLevelHookSize);

  // Fill in unused bytes with int 3 padders.
  if (size < MaxLowLevelHookSize) {
    writer.Memset(0xCC, (MaxLowLevelHookSize - size));
  }

  FlushInstructionCache(GetCurrentProcess(), pLowLevelHook, size);
  return size;
}

// =====================================================================================================================
Status PatchContext::LowLevelHook(
  TargetPtr                pAddress,
  Span<RegisterInfo>       registers,
  const FunctionRef&       pfnHookCb,
  const LowLevelHookInfo&  info)
{
  status_ = (status_   != Status::Ok) ? status_                     :
            (pAddress  == nullptr)    ? Status::FailInvalidPointer  :
            (pfnHookCb == nullptr)    ? Status::FailInvalidCallback : Status::Ok;

  pAddress = MaybeFixTargetPtr(pAddress);

  void*      pTrampoline     = nullptr;
  uint8      overwrittenSize = 0;
  size_t     trampolineSize  = 0;
  uint8      offsetLut[MaxOverwriteSize] = { };
  InsnVector insns;

  if (status_ == Status::Ok) {
    // Validate the callback signature and register options.
    const Call convention = pfnHookCb.Signature().convention;
    if ((convention != Call::Cdecl) && (convention != Call::Default) && (convention != Call::Unknown)) {
      status_ = Status::FailInvalidCallback;
    }
    else for (const auto& reg : registers) {
      if (((reg.type != IF_X86_32(Register::Esp) IF_X86_64(Register::Rsp)) || reg.byReference) && (reg.offset != 0)) {
        status_ = Status::FailInvalidCallback;
        break;
      }
    }
  }

  if (status_ == Status::Ok) {
    // Destroy any existing trampoline or functor.
    // ** TODO Be able to handle stacking multiple hooks; for now use of multiple PatchContexts can mostly do that.
    Revert(pAddress);
  }

  if (status_ == Status::Ok) {
    status_ = FindHookPatchRegion(pAddress, &overwrittenSize, &insns, sizeof(Jmp32));
  }

  if (status_ == Status::Ok) {
    if (overwrittenSize >= sizeof(Jmp32)) {
      const bool withinOverwrite = (info.pDefaultReturnAddr >= uintptr(pAddress)) &&
                                   (info.pDefaultReturnAddr <  PtrInc(pAddress, overwrittenSize));
      if ((info.noCustomReturnAddr == false) || (info.pDefaultReturnAddr == nullptr) || withinOverwrite) {
        status_ = CreateTrampoline(
          pAddress, pAllocator_, insns, overwrittenSize, &pTrampoline, &trampolineSize, MaxLowLevelHookSize, offsetLut);
      }
      else {
        // There's no conditions in which the callback could return into the overwritten code, so skip copying it.
        pTrampoline    = pAllocator_->Alloc(MaxLowLevelHookSize, CodeAlignment);
        trampolineSize = MaxLowLevelHookSize;
        status_ = (pTrampoline != nullptr) ? Status::Ok : Status::FailMemAlloc;
      }
    }
    else {
      status_ = Status::FailInstallHook;
    }
  }

  if (status_ == Status::Ok) {
    if (pTrampoline != nullptr) {
      // Initialize low-level hook code.
      const size_t usedSize = CreateLowLevelHookTrampoline(
        pTrampoline, registers, pAddress, pfnHookCb, moduleRelocDelta_, offsetLut, overwrittenSize, info);

      PATCHER_PACK_STRUCT
      struct {
        Jmp32 instruction;
        uint8 pad[MaxOverwriteSize - sizeof(Jmp32)];
      } jmp;
      PATCHER_END_PACK_STRUCT

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
    entry.trackedAllocs.Emplace(pTrampoline, trampolineSize);
    entry.pFunctorObj = pfnHookCb.Functor();
  }
  else if (pTrampoline != nullptr) {
    pAllocator_->Free(pTrampoline);
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
    std::vector<void*>            farThunks;
    std::unordered_set<uint16>    forwardExportOrdinals;
    std::map<std::string, uint16> namesToOrdinals;  // Name table must be sorted, so use map rather than unordered_map.

    IMAGE_EXPORT_DIRECTORY* pOldExportTable = nullptr;
    char moduleName[MAX_PATH] = "";  // ** TODO This won't work with large paths

    if ((pExportDataDir->VirtualAddress == 0) || (pExportDataDir->Size == 0)) {
      // Module has no export table.
      GetModuleFileNameA(static_cast<HMODULE>(hModule_), &moduleName[0], sizeof(moduleName));  // ** TODO Strip path
      exports.reserve(exportInfos.Length());
    }
    else {
      // Module has an export table.
      pOldExportTable = PtrInc<IMAGE_EXPORT_DIRECTORY*>(hModule_, pExportDataDir->VirtualAddress);
      strncpy_s(
        &moduleName[0], sizeof(moduleName), PtrInc<char*>(hModule_, pOldExportTable->Name), _TRUNCATE);

      auto*const pFunctions    = PtrInc<uint32*>(hModule_, pOldExportTable->AddressOfFunctions);
      auto*const pNames        = PtrInc<uint32*>(hModule_, pOldExportTable->AddressOfNames);
      auto*const pNameOrdinals = PtrInc<uint16*>(hModule_, pOldExportTable->AddressOfNameOrdinals);

      // Copy the module's exports.
      exports.reserve(pOldExportTable->NumberOfFunctions + exportInfos.Length());
      for (uint32 i = 0; i < pOldExportTable->NumberOfNames; ++i) {
        namesToOrdinals.emplace_hint(namesToOrdinals.end(),
                                     std::piecewise_construct,
                                     std::forward_as_tuple(PtrInc<const char*>(hModule_, pNames[i])),
                                     std::forward_as_tuple(pNameOrdinals[i]));
      }
      for (uint32 i = 0; i < pOldExportTable->NumberOfFunctions; ++i) {
        void*const pExportAddress = PtrInc(hModule_, pFunctions[i]);
        if ((pExportAddress >= pOldExportTable) && (pExportAddress < PtrInc(pOldExportTable, pExportDataDir->Size))) {
          forwardExportOrdinals.insert(static_cast<uint16>(exports.size()));
        }
        exports.emplace_back(pExportAddress);
      }
    }

    // Overlay our exports we want to inject.
    for (uint16 i = 0, nextIndex = uint16(exports.size()); (status_ == Status::Ok) && (i < exportInfos.Length()); ++i) {
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
    static constexpr size_t HeaderSize = sizeof(IMAGE_EXPORT_DIRECTORY);
    const size_t addressTableSize      = sizeof(void*)  * exports.size();
    const size_t namePtrTableSize      = sizeof(void*)  * namesToOrdinals.size();
    const size_t nameOrdinalTableSize  = sizeof(uint16) * namesToOrdinals.size();

    size_t totalNameStrlen = (strlen(moduleName) + 1);
    for (const auto& name : namesToOrdinals) {
      totalNameStrlen += (name.first.length() + 1);
    }

    size_t totalForwardStrlen = 0;
    for (const auto& ordinal : forwardExportOrdinals) {
      totalForwardStrlen += (strlen(static_cast<const char*>(exports[ordinal])) + 1);
    }

    const size_t allocSize =
      (HeaderSize + addressTableSize + namePtrTableSize + nameOrdinalTableSize + totalNameStrlen + totalForwardStrlen);
    void*const pAllocation = pAllocator_->Alloc(allocSize);  // We must allocate this within 32-bit signed addressing.

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
      pHeader->NumberOfFunctions     = static_cast<DWORD>(exports.size());
      pHeader->NumberOfNames         = static_cast<DWORD>(namesToOrdinals.size());
      pHeader->AddressOfFunctions    = static_cast<DWORD>(PtrDelta(pAddressTable,     hModule_));  // By RVA
      pHeader->AddressOfNames        = static_cast<DWORD>(PtrDelta(pNameTable,        hModule_));  // By RVA
      pHeader->AddressOfNameOrdinals = static_cast<DWORD>(PtrDelta(pNameOrdinalTable, hModule_));  // By RVA

      // Set up the rest of the new export table: Export Address Table, Export Name Pointer Table, Export Ordinal Table,
      // Export Name Table.
      AppendString(&pStringBuffer, moduleName);

      for (uint32 i = 0; ((status_ == Status::Ok) && (i < exports.size())); ++i) {
        if (forwardExportOrdinals.count(i) == 0) {
          size_t exportRva = (exports[i] != nullptr) ? PtrDelta(exports[i], hModule_) : 0;

          if (IsFarDisplacement(exportRva)) {
            // Exports must be within 32-bit addressing.
            void*const pFarThunk = pAllocator_->Alloc(FarThunkSize, CodeAlignment);
            status_ = (pFarThunk != nullptr) ? CreateFarThunk(pFarThunk, exports[i]) : Status::FailMemAlloc;

            if (status_ == Status::Ok) {
              exportRva = PtrDelta(pFarThunk, hModule_);
              farThunks.push_back(pFarThunk);
            }
          }

          pAddressTable[i] = static_cast<uint32>(exportRva);
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

      const bool previouslyEdited = HasPatched(pExportDataDir);

      // Modify the module's header to point to our new export table.
      Write(pExportDataDir, IMAGE_DATA_DIRECTORY{ DWORD(PtrDelta(pAllocation, hModule_)), DWORD(allocSize) });

      if (status_ == Status::Ok) {
        // Add export table allocation and far thunk info to the history tracker entry for this patch so we can clean it
        // up later.
        auto& entry = *historyAt_[pExportDataDir];

        if (previouslyEdited && (entry.trackedAllocs.empty() == false)) {
          // If we previously had injected exports, we need to clean up the heap allocation for the old table.
          pAllocator_->Free(entry.trackedAllocs[0].first);
        }
        else {
          entry.trackedAllocs.Emplace();  // Ensure element 0 exists, which is reserved for the table pointer.
        }

        entry.trackedAllocs.Grow(farThunks.size());
        entry.trackedAllocs[0] = { pAllocation, 0 };
        for (void* pFarThunk : farThunks) {
          entry.trackedAllocs.Emplace(pFarThunk, FarThunkSize);
        }
      }
      else {
        pAllocator_->Free(pAllocation);
        for (void* pFarThunk : farThunks) {
          pAllocator_->Free(pFarThunk);
        }
      }
    }
    else {
      status_ = Status::FailMemAlloc;
    }
  }

  return status_;
}

// =====================================================================================================================
void* Allocator::Alloc(
  size_t  size,
  size_t  align)
{
  std::lock_guard<std::mutex> lock(lock_);

  void* pMemory = nullptr;

  if (pBlocks_.empty() == false) {
    // Try to use an existing block, if there's one with enough free space.
    auto*const pHeader = pBlocks_.front();
    void*const pBegin  = PtrAlign(PtrInc(pHeader->pNextAddr, sizeof(void*)), align);
    void*const pEnd    = PtrInc(pBegin, size);

    if (pEnd <= pHeader->pEndAddr) {
      // Store a pointer to the block header just before the aligned output pointer so we can free it later.
      static_cast<BlockHeader**>(pBegin)[-1] = pHeader;
      pMemory            = pBegin;
      pHeader->pNextAddr = pEnd;
      ++pHeader->refCount;

      // Reorder the heap, since this block's free space has shrunk.
      std::pop_heap(pBlocks_.begin(),  pBlocks_.end(), FreeBlockSizeCompare);
      std::push_heap(pBlocks_.begin(), pBlocks_.end(), FreeBlockSizeCompare);
    }
  }

  if (pMemory == nullptr) {
    // We need to commit a new block, and possibly reserve a new slab.
    void*        pAlloc    = nullptr;
    const size_t pagesSize = Align((sizeof(BlockHeader) + sizeof(void*) + align + size), PageSize());
    const size_t slabsSize = Align(pagesSize, SlabSize());

    // Reserve a new memory slab if needed.
    if (pSlabs_.empty() || (PtrInc(pNextBlock_, pagesSize) >= PtrInc(pSlabs_.back(), SlabSize()))) {
      // Try to find a suitable placement area within the VA range.  We may need to make multiple attempts due to race
      // conditions that can happen in between querying for free memory and actually trying to reserve it.
      for (void* p = pNextBlock_; (pAlloc == nullptr) && ((p = FindNextRegion(pNextBlock_, slabsSize)) != nullptr);) {
        pAlloc = VirtualAlloc(p, slabsSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      }

      if (pAlloc != nullptr) {
        pSlabs_.push_back(pAlloc);
      }
    }
    else {
      pAlloc = pNextBlock_;
    }

    if (pAlloc != nullptr) {
      // If the allocation is bigger than one slab (>64 KB), then commit as many slabs as required as one single block.
      // Otherwise, only commit as many pages as required to fit the requested size as one block.
      const size_t blockSize = (pagesSize > SlabSize()) ? slabsSize : pagesSize;

      pMemory = VirtualAlloc(pAlloc, blockSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      assert(pMemory != nullptr);

      auto*const pHeader = static_cast<BlockHeader*>(pMemory);
      pMemory = PtrAlign(PtrInc(pMemory, sizeof(BlockHeader) + sizeof(void*)), align);
      // Store a pointer to the block header just before the aligned output pointer so we can free it later.
      static_cast<void**>(pMemory)[-1] = pHeader;

      pNextBlock_        = PtrInc(pHeader, blockSize);
      pHeader->pNextAddr = PtrInc(pMemory, size);
      pHeader->pEndAddr  = pNextBlock_;
      pHeader->refCount  = 1;

      pBlocks_.push_back(pHeader);
      std::push_heap(pBlocks_.begin(), pBlocks_.end(), FreeBlockSizeCompare);
    }
  }

  return pMemory;
}

// =====================================================================================================================
void Allocator::Free(
  void*  pMemory)
{
  if (pMemory != nullptr) {
    std::lock_guard<std::mutex> lock(lock_);

    auto*const pHeader = static_cast<BlockHeader**>(pMemory)[-1];
    assert(pHeader->refCount != 0);

    if (--pHeader->refCount == 0) {
      // Rewind the block to its beginning, "freeing" it.  For simplicity, we do not decommit, coalesce, or split.
      pHeader->pNextAddr = PtrInc(pHeader, sizeof(BlockHeader));
      std::make_heap(pBlocks_.begin(), pBlocks_.end(), FreeBlockSizeCompare);  // ** TODO This could be optimized
    }
  }
}

// =====================================================================================================================
void* Allocator::FindNextRegion(
  void*   pNearAddr,
  size_t  sizeNeeded)
{
  void*        pRegion  = nullptr;
  const size_t slabSize = SlabSize();

  void*const pMaxAddr    = (std::min)(SystemInfo().lpMaximumApplicationAddress, PtrInc(pVaStart_, VaRange));
  void*const pMinAddr    =
    PtrAlign((std::max)({ SystemInfo().lpMinimumApplicationAddress, pVaStart_, (void*)(slabSize) }), slabSize);
  void*const pOriginAddr = (std::max)(pMinAddr, PtrAlign(pNearAddr, slabSize));

  auto SearchRegions = [&pRegion, sizeNeeded, slabSize](void* pBegin, void* pEnd) {
    for (void* pTryAddr = pBegin; PtrInc(pTryAddr, sizeNeeded) < pEnd;) {
      MEMORY_BASIC_INFORMATION memInfo;

      if (VirtualQuery(pTryAddr, &memInfo, sizeof(memInfo)) > offsetof(MEMORY_BASIC_INFORMATION, State)) {
        if ((memInfo.State == MEM_FREE) && (memInfo.RegionSize >= sizeNeeded)) {
          pRegion = pTryAddr;
          break;
        }

        pTryAddr = PtrAlign(PtrInc(memInfo.BaseAddress, memInfo.RegionSize), slabSize);
      }
      else {
        pTryAddr = PtrInc(pTryAddr, slabSize);
      }
    }
  };

  // Try to find a free memory region after pNearAddr.
  SearchRegions(pOriginAddr, pMaxAddr);

  if (pRegion == nullptr) {
    // Try to find a free memory region before pNearAddr.
    SearchRegions(pMinAddr, pOriginAddr);
  }

  return pRegion;
}

} // Patcher
