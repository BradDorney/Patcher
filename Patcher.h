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

#pragma once

#include <utility>
#include <tuple>
#include <list>
#include <vector>
#include <unordered_map>
#include <initializer_list>

#include "PatcherUtil.h"

namespace Patcher {

/// @brief  RAII memory patch context class.  Allows for safe writes into process memory.
///
/// The first time some memory is modified, the original data is tracked, and is automatically restored when the context
/// object instance is destroyed.
///
/// Methods that return a Status also update an internally-tracked status.  If the internal status is an error, all
/// subsequent calls to those methods become a no-op and return the last error until it is reset by RevertAll().
///
/// @note  Calling methods with address provided as uintptr_t will cause address to be relocated.
///        Calling methods with address provided as a pointer type will not relocate.
class PatchContext {
public:
  /// Default constructor creates a patcher context for the process's base module.
  PatchContext() : PatchContext(static_cast<const char*>(nullptr), false) { }

  /// Constructor to create a patcher context for the given process module name, and (optionally) loads the module.
  explicit PatchContext(const char* pModuleName, bool loadModule = false);

  /// Constructor to create a patcher context for the given HMODULE.
  explicit PatchContext(void* hModule);

  PatchContext(const PatchContext&)            = delete;
  PatchContext& operator=(const PatchContext&) = delete;

  /// Destructor.  Reverts all patches owned by this context, and if it had opened a module, releases it as well.
  ~PatchContext();

  /// Gets the status of the patcher. This can be called once after multiple Write/Memcpy/Hook/etc. calls, rather than
  /// checking the returned status of each call individually.
  Status GetStatus() const { return status_; }

  ///@{
  /// Fixes up a raw address, adjusting it for module base relocation.
  template <typename T = void>
  T* FixPtr(uintptr_t address) const { return FixPtr(reinterpret_cast<T*>(address)); }
  template <typename T>
  T* FixPtr(T* pAddress) const {
    assert(pAddress != nullptr);
    return static_cast<T*>(PtrInc(static_cast<void*>(pAddress), moduleRelocDelta_));
  }
  ///@}

  /// Writes the given value to process memory.
  template <typename T>
  Status Write(TargetPtr pAddress, const T& newValue) { return Memcpy<sizeof(T)>(pAddress, &newValue); }

  /// Writes the given bytes to process memory.
  Status WriteBytes(TargetPtr pAddress, std::initializer_list<uint8> bytes)
    { return Memcpy(pAddress, bytes.begin(), bytes.size()); }

  ///@{
  /// Adds the specified process memory to the history tracker so it can be restored via Revert().
  Status Touch(TargetPtr pAddress, size_t size);
  template <typename T>
  Status Touch(T*        pAddress) { return Touch(pAddress, sizeof(T)); };
  ///@}

  ///@{
  /// Hooks the beginning of a function in process memory, and optionally returns a pointer to a trampoline function
  /// that can be used to call the original function.  New function's signature must match the original's.
  ///
  /// @param [in]  pAddress        Address of where to insert the hook.
  /// @param [in]  pfnNewFunction  Pointer to the hook function to call instead.
  /// @param [out] pPfnTrampoline  (Optional) Pointer to where to store a callback pointer to the original function.
  ///
  /// @note  32-bit x86 only.
  Status Hook(TargetPtr pAddress, FunctionPtr pfnNewFunction, void* pPfnTrampoline = nullptr);
  template <typename T>
  Status Hook(TargetPtr pAddress, FunctionPtr pfnNewFunction, T**   pPfnTrampoline = nullptr)
    { return Hook(pAddress, pfnNewFunction, static_cast<void*>(pPfnTrampoline)); }
  ///@}

  /// Hooks a function call instruction in process memory, replacing its original target address.
  /// New function's signature must match the original's.
  ///
  /// @param [in] pAddress        Address of the call instruction to fix up.
  /// @param [in] pfnNewFunction  Pointer to the new function to call instead.
  ///
  /// @note  32-bit x86 only.
  Status HookCall(TargetPtr pAddress, FunctionPtr pfnNewFunction);

  ///@{
  /// @brief  Hooks an instruction (almost) anywhere in process memory.  Read and write access to the state of standard
  ///         registers is provided via function args, and control flow can be manipulated via the returned value.
  ///
  /// Example usage: LowLevelHook(0x402044, [](Eax<int>& a1, Esi<bool> a2) { ++a1;  return a2 ? 0 : 0x402107; })
  ///                LowLevelHook(0x5200AF, { Register::Eax, Register::Edx }, [](int64& val) { val = -val; })
  ///
  /// Available registers: [Eax, Ecx, Edx, Ebx, Esi, Edi, Ebp, Esp, Eflags].  Arg types must fit within register size.
  /// To write to registers, declare args with >& or >*, e.g. Eax<int>&, Ecx<int>*, Ebp<char*>&, Edx<int&>&, Edi<int*>*
  /// Hook must use cdecl, and return either void (with @ref LowLevelHookOpt::NoCustomReturnAddr or template deduction);
  /// or an address to jump to, where nullptr = original address (addresses within the overwritten area are allowed).
  ///
  /// @warning  This requires 5-19 bytes at pAddress; if the last N-1 bytes overlap any jump targets, this could crash.
  /// @note     32-bit x86 only.
  Status LowLevelHook(TargetPtr                     pAddress,         ///< [in] Address of where to insert the hook.
                      const std::vector<Register>&  registers,        ///< [in] Registers to pass to the hook function.
                      uint32                        byRefMask,        ///< [in] Bitmask of args to pass by reference.
                      FunctionPtr                   pfnHookCb,        ///< [in] User hook callback (function or lambda).
                      uint32                        options    = 0);  ///< [in] Options.  See @ref LowLevelHookOpt.
  ///< Insert a low-level hook with a callback function that takes RegisterArgs or no args.
  template <typename P, typename R, typename... Args>
  Status LowLevelHook(P pAddress, R (PATCHER_CDECL* pfnHookCb)(Args...), uint32 options = 0) {
    const auto address = static_cast<Conditional<std::is_pointer<P>::value, void*, uintptr_t>>(pAddress);
    options |= LowLevelHookOpt::GetDefaults<R>();
    return LowLevelHook(address, { GetRegisterArgId<Args>()... }, MakeByRefMask<Args...>(), pfnHookCb, options);
  }
  ///< Insert a low-level hook with a callback function that takes a struct pointer or reference.
  template <typename P, typename R, typename A>
  Status LowLevelHook(
    P pAddress, const std::vector<Register>& registers, R (PATCHER_CDECL* pfnHookCb)(A), uint32 options = 0)
  {
    const auto address = static_cast<Conditional<std::is_pointer<P>::value, void*, uintptr_t>>(pAddress);
    options |= (LowLevelHookOpt::ArgsAsStructPtr | LowLevelHookOpt::GetDefaults<R>());
    return LowLevelHook(address, registers, 0, pfnHookCb, options);
  }
  ///< Insert a low-level hook with a non-capturing lambda that takes RegisterArgs or no args.
  template <typename P, typename Lambda, typename IsNonCapturingLambda = decltype(LambdaPtr(std::declval<Lambda>()))>
  Status LowLevelHook(P pAddress, const Lambda& pfnHookCb, uint32 options = 0)
    { return LowLevelHook(pAddress, CdeclLambdaPtr(pfnHookCb), options); }
  ///< Insert a low-level hook with a non-capturing lambda that takes a struct pointer or reference.
  template <typename P, typename Lambda, typename IsNonCapturingLambda = decltype(LambdaPtr(std::declval<Lambda>()))>
  Status LowLevelHook(P pAddress, const std::vector<Register>& registers, const Lambda& pfnHookCb, uint32 options = 0)
    { return LowLevelHook(pAddress, registers, CdeclLambdaPtr(pfnHookCb), options); }
  ///@}

  ///@{
  /// Replaces all static, direct pointer references to a global by scanning the module's .reloc section for any
  /// references to it.
  ///
  /// @param [in]  pOldGlobal  Pointer to the old global we want to replace.
  /// @param [in]  size        Size in bytes of the global.
  /// @param [in]  pNewGlobal  Pointer to the new global we want to replace all references to pOldGlobal with.
  /// @param [out] pRefsOut    (Optional) Pointer to a vector to contain all locations that have been patched up.
  Status ReplaceReferencesToGlobal(
    TargetPtr pOldGlobal, size_t size, const void* pNewGlobal, std::vector<void*>* pRefsOut = nullptr);
  template <typename T>
  Status ReplaceReferencesToGlobal(TargetPtr pOldGlobal, const T* pNewGlobal, std::vector<void*>* pRefsOut = nullptr)
    { return ReplaceReferencesToGlobal(pOldGlobal, sizeof(T), pNewGlobal, pRefsOut); }
  ///@}

  /// Adds or modifies export table entries in the module.
  ///
  /// There are 3 modes of exporting:
  ///  - Export by name:     Exports by decorated symbol name.
  ///  - Export by ordinal:  Exports by ordinal (index); used by older exes or for anonymizing exports.
  ///  - Forwarded export:   Forwards an import (by name) from another module.  Often used by OS and shim libraries.
  ///                        Injecting new (rather than modifying existing) forwarded exports is currently unsupported.
  ///
  /// Injecting exports with the same name or ordinal as existing exports overrides them.  Otherwise, they are added as
  /// new export entries.  If the export address is nullptr, the entry will be deleted instead.
  ///
  /// @note  32-bit x86 only.
  Status EditExports(const std::vector<ExportInfo>& exportInfos);

  /// Safe memcpy into process memory.
  Status Memcpy(TargetPtr pAddress, const void* pSrc, size_t size);
  /// Optimized safe memcpy that allows the compiler to inline the instructions when the size is known at compile time.
  template <size_t Size>
  Status Memcpy(TargetPtr pAddress, const void* pSrc);

  /// Safe memset of process memory.
  Status Memset(TargetPtr pAddress, uint8 value, size_t count);
  /// Optimized safe memset that allows the compiler to inline the instructions when the size is known at compile time.
  template <size_t Count>
  Status Memset(TargetPtr pAddress, uint8 value);

  ///@{
  /// In-place constructs an object within the module's memory.
  template <typename T, typename... Args>
  Status Construct(T*        pAddress, Args&&... args);
  template <typename T, typename... Args>
  Status Construct(uintptr_t address,  Args&&... args)
    { return Construct<T>(FixPtr<T*>(address), std::forward(args)...); }
  ///@}

  /// Freezes all other process threads, preventing potential race conditions between patching code and executing it.
  /// @note  32-bit x86 only.
  Status LockThreads();
  /// Unfreezes all other process threads after having used LockThreads().
  Status UnlockThreads();

  /// Reverts a patch that was previously written beginning at the given address.
  Status Revert(TargetPtr pAddress);
  /// Reverts exports that had been injected by EditExports().
  Status RevertExports();
  /// Reverts all patches this context had applied, and resets the context status to a clean state.
  Status RevertAll();

  /// If this PatchContext has loaded a module, releases its active handle to it.
  Status ReleaseModule();

  /// Returns the number of active patches.
  uint32 NumPatches() const { return history_.size(); }

private:
  void Init();

  // Helper functions for barriering around memory writes.
  uint32 BeginDeProtect(void* pAddress, size_t size);
  void   EndDeProtect(void* pAddress, size_t size, uint32 oldAttr);
  Status AdvanceThreads(void* pAddress, size_t size);

  bool      hasModuleRef_;
  void*     hModule_;
  intptr_t  moduleRelocDelta_;
  uint32    moduleHash_;
  Status    status_;

  static constexpr size_t StorageSize = 8;

  // Mappings of addresses to (old memory copy, trampoline function allocation (optional), trampoline size (optional)).
  std::list<std::tuple<void*, ByteArray<StorageSize>, void*, size_t>>  history_;
  std::unordered_map<void*, decltype(history_)::iterator>              historyAt_;

  // Threads locked by LockThreads() (pair of handle, program counter).  AdvanceThreads() may temporarily resume these.
  std::vector<std::pair<uint32, uintptr_t>>  frozenThreads_;
};

// =====================================================================================================================
template <size_t Size>
Status PatchContext::Memcpy(
  TargetPtr    pAddress,
  const void*  pSrc)
{
  assert((pAddress != nullptr) && (pSrc != nullptr));
  void*const pDst = pAddress.ShouldRelocate() ? FixPtr(pAddress) : static_cast<void*>(pAddress);

  const uint32 oldAttr = BeginDeProtect(pDst, Size);

  if (status_ == Status::Ok) {
    memcpy(pDst, pSrc, Size);
    EndDeProtect(pDst, Size, oldAttr);
  }

  return status_;
}

// =====================================================================================================================
template <size_t Count>
Status PatchContext::Memset(
  TargetPtr  pAddress,
  uint8      value)
{
  assert(pAddress != nullptr);
  void*const pDst = pAddress.ShouldRelocate() ? FixPtr(pAddress) : static_cast<void*>(pAddress);

  const uint32 oldAttr = BeginDeProtect(pDst, Count);

  if (status_ == Status::Ok) {
    memset(pDst, value, Count);
    EndDeProtect(pDst, Count, oldAttr);
  }

  return status_;
}

// =====================================================================================================================
template <typename T, typename... Args>
Status PatchContext::Construct(
  T*         pAddress,
  Args&&...  args)
{
  assert(pAddress != nullptr);
  const uint32 oldAttr = BeginDeProtect(pAddress, sizeof(T));

  if (status_ == Status::Ok) {
    new(pAddress) T(std::forward(args)...);
    EndDeProtect(pAddress, sizeof(T), oldAttr);
  }

  return status_;
}

} // Patcher
