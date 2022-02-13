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

#pragma once

#include "PatcherImpl.h"

/// Status enum returned by PatchContext methods.
enum class PatcherStatus : int32_t {
  Ok = 0,

  FailUnknown         = -1,
  FailUnsupported     = -2,
  FailInvalidPointer  = -3,
  FailInvalidCallback = -4,
  FailMemAlloc        = -5,
  FailMemFree         = -6,
  FailDeProtectMem    = -7,
  FailLockThreads     = -8,
  FailDisassemble     = -9,
  FailInstallHook     = -10,
  FailModuleUnloaded  = -11,
  FailInvalidModule   = -12,
};

namespace Patcher {

namespace Util {
/// Constant to specify to PatchContext::Hook() that the first lambda capture (which must be by value) is pfnTrampoline.
/// For other functor types, it is recommended that you use a pointer-to-member-variable or offsetof() instead.
constexpr size_t SetCapturedTrampoline = 0;


///@{ Converts any (non-overloaded) lambda or functor to a FunctionPtr object (of the specified calling convention).
///   This can be passed to PatchContext methods, be used as a callable, and implicitly converts to a function pointer.
///   If created from a non-empty type, then the returned FunctionPtr needs to be kept alive or referenced by a patch.
#define PATCHER_CREATE_FUNCTOR_INVOKER_DEF(convention, name)  template <typename T>  \
Impl::FunctorRef<T, Call::name> name##Functor(T&& f) { return Impl::FunctorRef<T, Call::name>(std::forward<T>(f)); }
template <Call C = Call::Default, typename T = void>
Impl::FunctorRef<T, C>                Functor(T&& f) { return Impl::FunctorRef<T, C>(std::forward<T>(f));          }
PATCHER_EMIT_CALLING_CONVENTIONS(PATCHER_CREATE_FUNCTOR_INVOKER_DEF);
///@}
} // Util


/// Settings passed to LowLevelHook() for hook callback behavior, performance, etc.  Some flags can be template-deduced.
struct LowLevelHookInfo {
  uint32 noCustomReturnAddr  :  1;  ///< Callback return address not allowed (i.e. callback function returns void).
  uint32 noBaseRelocReturn   :  1;  ///< Do not auto-adjust callback return address for module base relocation.
  uint32 noShortReturnAddr   :  1;  ///< Assume callback return address can't overlap overwritten area (x86: 5 bytes)
  uint32 noNullReturnDefault :  1;  ///< Do not reinterpret callback return address of 0/nullptr to default address.
  uint32 argsAsStructPtr     :  1;  ///< Args are passed to the callback as a pointer to a struct that contains them.
  uint32 noAlignStackPtr     :  1;  ///< Skip aligning the stack pointer. Faster, but may break float and vector ops.
  uint32 noRestoreFlagsReg   :  1;  ///< Do not save/restore the flags register state, which can be expensive.
  uint32 debugBreakpoint     :  1;  ///< Adds a debug breakpoint to the start of the trampoline code.
  uint32 reserved            : 24;  ///< Reserved for future use.

  Impl::TargetPtr pDefaultReturnAddr; ///< If set, overrides the default return address when callback returns nullptr or
                                      ///  void.  Otherwise, the default return address will be to the original code.

  uint32 reserveStackSize;  ///< Size in bytes of extra stack space to reserve.  Set this if you intend to modify ESP to
                            ///  allocate space on the stack (up to a maximum of the specified size).
};

namespace Impl {
/// @internal  Sets default LowLevelHook options based on the callback's function signature.
template <typename R, Call C, bool V, typename... A>
constexpr LowLevelHookInfo& DeduceLowLevelHookSettings(LowLevelHookInfo& info, Impl::FuncSig<R, C, V, A...>)
  { info.noBaseRelocReturn = std::is_pointer<R>::value; info.noCustomReturnAddr = std::is_void<R>::value; return info; }
} // Impl


namespace Registers {
#if PATCHER_X86_32
/// x86_32 Register types passed to PatchContext::LowLevelHook().
enum class Register : uint8 { Eax = 0, Ecx, Edx, Ebx, Esi, Edi, Ebp, GprLast = Ebp, Esp, Eflags, Count };

///@{ Shorthand aliases for RegisterArgs of each x86_32 Register type.  Used for LowLevelHook() hook functions.
template <typename T>                     using Eax    = Impl::RegisterArg<Register::Eax,    T>;
template <typename T>                     using Ecx    = Impl::RegisterArg<Register::Ecx,    T>;
template <typename T>                     using Edx    = Impl::RegisterArg<Register::Edx,    T>;
template <typename T>                     using Ebx    = Impl::RegisterArg<Register::Ebx,    T>;
template <typename T>                     using Esi    = Impl::RegisterArg<Register::Esi,    T>;
template <typename T>                     using Edi    = Impl::RegisterArg<Register::Edi,    T>;
template <typename T>                     using Ebp    = Impl::RegisterArg<Register::Ebp,    T>;
template <typename T, uint32 Offset = 0>  using Esp    = Impl::RegisterArg<Register::Esp,    T, Offset>;
template <typename T>                     using Eflags = Impl::RegisterArg<Register::Eflags, T>;
///@}
#elif PATCHER_X86_64
/// x86_64 Register types passed to PatchContext::LowLevelHook().
enum class Register : uint8
  { Rax = 0, Rcx, Rdx, Rbx, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rbp, GprLast = Rbp, Rsp, Rflags, Count };

///@{ Shorthand aliases for RegisterArgs of each x86_64 Register type.  Used for LowLevelHook() hook functions.
template <typename T>                     using Rax    = Impl::RegisterArg<Register::Rax,    T>;
template <typename T>                     using Rcx    = Impl::RegisterArg<Register::Rcx,    T>;
template <typename T>                     using Rdx    = Impl::RegisterArg<Register::Rdx,    T>;
template <typename T>                     using Rbx    = Impl::RegisterArg<Register::Rbx,    T>;
template <typename T>                     using Rsi    = Impl::RegisterArg<Register::Rsi,    T>;
template <typename T>                     using Rdi    = Impl::RegisterArg<Register::Rdi,    T>;
template <typename T>                     using R8     = Impl::RegisterArg<Register::R8,     T>;
template <typename T>                     using R9     = Impl::RegisterArg<Register::R9,     T>;
template <typename T>                     using R10    = Impl::RegisterArg<Register::R10,    T>;
template <typename T>                     using R11    = Impl::RegisterArg<Register::R11,    T>;
template <typename T>                     using R12    = Impl::RegisterArg<Register::R12,    T>;
template <typename T>                     using R13    = Impl::RegisterArg<Register::R13,    T>;
template <typename T>                     using R14    = Impl::RegisterArg<Register::R14,    T>;
template <typename T>                     using R15    = Impl::RegisterArg<Register::R15,    T>;
template <typename T>                     using Rbp    = Impl::RegisterArg<Register::Rbp,    T>;
template <typename T, uint32 Offset = 0>  using Rsp    = Impl::RegisterArg<Register::Rsp,    T, Offset>;
template <typename T>                     using Rflags = Impl::RegisterArg<Register::Rflags, T>;
///@}
#endif
} // Registers


/// Export insertion/modification info passed to PatchContext::EditExports().
struct ExportInfo {
  ///@{ Constructor for defining an export by symbol name.
  constexpr ExportInfo(void*  pAddress, const char* pSymbolName)
    : type(ByName),  pAddress(pAddress), pSymbolName(pSymbolName) { }
  constexpr ExportInfo(uintptr address, const char* pSymbolName)
    : type(ByNameFix), address(address), pSymbolName(pSymbolName) { }
  ///@}

  ///@{ Constructor for defining an export by ordinal.
  constexpr ExportInfo(void*  pAddress, uint16 ordinal) : type(ByOrdinal),  pAddress(pAddress), ordinal(ordinal) { }
  constexpr ExportInfo(uintptr address, uint16 ordinal) : type(ByOrdinalFix), address(address), ordinal(ordinal) { }
  ///@}

  /// Constructor for defining a forwarded export symbol.
  template <typename T, typename = Impl::EnableIf<std::is_same<T, char>::value>>
  constexpr ExportInfo(const T* pForwardName, const char* pSymbolName)
    : type(Forwarded), pForwardName(pForwardName), pSymbolName(pSymbolName) { }

  enum : uint32 { ByName = 0, ByNameFix, ByOrdinal, ByOrdinalFix, Forwarded }
    type;

  union {
    void*        pAddress;
    uintptr      address;
    const char*  pForwardName;
  };

  union {
    const char*  pSymbolName;
    uint16       ordinal;
  };
};

} // Patcher
