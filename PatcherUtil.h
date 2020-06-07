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

#include <type_traits>
#include <cstdint>
#include <cassert>
#include <cstring>

/// Defines
#if defined(__clang__) || defined(__INTEL_CLANG_COMPILER)
# define PATCHER_CLANG 1
#elif defined(__INTEL_COMPILER) || defined(__ICC) || defined(__ICL)
# define PATCHER_ICC   1
#elif defined(__GNUC__)
# define PATCHER_GCC   1  // Also matches other GCC-compliant compilers except for Clang and ICC.
#elif defined(_MSC_VER)
# define PATCHER_MSVC  1
#endif

#if defined(_M_IX86) || (defined(__i386__) && (defined(__x86_64__) == false))
# define PATCHER_X86    1
# define PATCHER_X86_32 1
#elif defined(_M_X64) || defined(__x86_64__)
# define PATCHER_X86    1
# define PATCHER_X86_64 1
#endif

#if PATCHER_MSVC || defined(__ICL)
# define PATCHER_CDECL      __cdecl
# define PATCHER_STDCALL    __stdcall
# define PATCHER_FASTCALL   __fastcall
# define PATCHER_THISCALL   __thiscall
# define PATCHER_VECTORCALL __vectorcall
# if defined(__ICL)
#  define PATCHER_REGCALL   __regcall
# else
#  define PATCHER_REGCALL
# endif
# define PATCHER_REGPARM(n)
# define PATCHER_SSEREGPARM
#elif defined(__GNUC__)
# define PATCHER_CDECL      __attribute((cdecl))
# define PATCHER_STDCALL    __attribute((stdcall))
# define PATCHER_FASTCALL   __attribute((fastcall))
# define PATCHER_THISCALL   __attribute((thiscall))
# define PATCHER_VECTORCALL __attribute((vectorcall))
# define PATCHER_REGCALL    __attribute((regcall))
# define PATCHER_REGPARM(n) __attribute((regparm(n)))
# define PATCHER_SSEREGPARM __attribute((sseregparm))
#endif

namespace Patcher {

/// Typedefs
using int8   = int8_t;
using int16  = int16_t;
using int32  = int32_t;
using int64  = int64_t;
using uint8  = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;

/// Status enum returned by PatchContext methods.
enum class Status : int32 {
  Ok = 0,

  FailUnknown        = -1,
  FailInvalidPointer = -2,
  FailMemAlloc       = -3,
  FailMemFree        = -4,
  FailDeProtectMem   = -5,
  FailLockThreads    = -6,
  FailDisassemble    = -7,
  FailModuleUnloaded = -8,
  FailInvalidModule  = -9,
  FailUnsupported    = -10,
};


/// Rounds value up to the nearest multiple of align, where align is a power of 2.
template <typename T>
constexpr T Align(T value, uint32 align) { return (value + static_cast<T>(align - 1)) & ~static_cast<T>(align - 1); }

///@{
/// Pointer arithmetic helpers.
inline void*       PtrInc(void*       p, size_t offset) { return static_cast<uint8*>(p)       + offset; }
inline const void* PtrInc(const void* p, size_t offset) { return static_cast<const uint8*>(p) + offset; }

inline void*       PtrDec(void*       p, size_t offset) { return static_cast<uint8*>(p)       - offset; }
inline const void* PtrDec(const void* p, size_t offset) { return static_cast<const uint8*>(p) - offset; }

inline size_t      PtrDelta(const void* pHigh, const void* pLow)
  { return static_cast<size_t>(static_cast<const uint8*>(pHigh) - static_cast<const uint8*>(pLow)); }

inline void*       PtrAlign(void*       p, uint32 align)
  { return reinterpret_cast<void*>(Align(reinterpret_cast<uintptr_t>(p), align)); }
inline const void* PtrAlign(const void* p, uint32 align)
  { return reinterpret_cast<const void*>(Align(reinterpret_cast<uintptr_t>(p), align)); }

template <typename T = uint32>
T PcRelPtr(const void* pFrom, size_t fromSize, const void* pTo)
  { return static_cast<T>(PtrDelta(pTo, PtrInc(pFrom, fromSize))); }
///@}

/// type_traits convenience aliases.
template <typename T>                       using RemovePointer      = typename std::remove_pointer<T>::type;
template <typename T>                       using RemoveReference    = typename std::remove_reference<T>::type;
template <typename T>                       using RemoveCv           = typename std::remove_cv<T>::type;
template <typename T>                       using RemoveCvRef        = RemoveCv<RemoveReference<T>>;
template <typename T>                       using RemoveAllExtents   = typename std::remove_all_extents<T>::type;
template <typename T>                       using AddLvalueReference = typename std::add_lvalue_reference<T>::type;
template <bool Condition, class T = void>   using EnableIf           = typename std::enable_if<Condition, T>::type;
template <bool Condition, class T, class F> using Conditional        = typename std::conditional<Condition, T, F>::type;
template <size_t Len, size_t Align>         using AlignedStorage     = typename std::aligned_storage<Len, Align>::type;
template <typename T>                       using Identity           = T;


///@{
/// @internal Helper template class used in converting non-capturing lambdas to function pointers.
template <typename>         struct LambdaInvokerImpl { using Pfn = void; };
template <typename Lambda>  using  Invoker = LambdaInvokerImpl<decltype(&Lambda::operator())>;

template <typename Lambda, typename ReturnType, typename... Args>
struct LambdaInvokerImpl<ReturnType(Lambda::*)(Args...) const> {
  static_assert(std::is_empty<Lambda>::value,  "Only non-capturing lambdas can be converted to function pointers.");
  static constexpr const Lambda* GetInvoker() { return nullptr; }  // Non-capturing lambdas are stateless.
  using Pfn = ReturnType(*)(Args...);

  static ReturnType PATCHER_CDECL      Cdecl(Args...      args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_STDCALL    Stdcall(Args...    args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_FASTCALL   Fastcall(Args...   args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_VECTORCALL Vectorcall(Args... args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_THISCALL   Thiscall(Args...   args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_REGCALL    Regcall(Args...    args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_REGPARM(1) Regparm1(Args...   args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_REGPARM(2) Regparm2(Args...   args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_REGPARM(3) Regparm(Args...    args) { return GetInvoker()->operator()(args...); }
  static ReturnType PATCHER_SSEREGPARM SseRegparm(Args... args) { return GetInvoker()->operator()(args...); }
};
///@}

#if __cpp_return_type_deduction  // Use C++14 auto return type to work around MSVC Intellisense bugs.
# define PATCHER_INVOKE(convention) constexpr auto*
#else
# define PATCHER_INVOKE(convention) constexpr decltype(&Invoker<T>::convention)
#endif

///@{
/// Helper functions to convert non-capturing lambdas to function pointers of any calling convention.
template <typename T> constexpr typename Invoker<T>::Pfn LambdaPtr(T   x) { return x; }
#if PATCHER_MSVC  // Use MSVC's builtin conversions.
template <typename T> PATCHER_INVOKE(Cdecl)      CdeclLambdaPtr(T      x) { return true ? x : &Invoker<T>::Cdecl;      }
template <typename T> PATCHER_INVOKE(Stdcall)    StdcallLambdaPtr(T    x) { return true ? x : &Invoker<T>::Stdcall;    }
template <typename T> PATCHER_INVOKE(Fastcall)   FastcallLambdaPtr(T   x) { return true ? x : &Invoker<T>::Fastcall;   }
template <typename T> PATCHER_INVOKE(Vectorcall) VectorcallLambdaPtr(T x) { return true ? x : &Invoker<T>::Vectorcall; }
#else
template <typename T> PATCHER_INVOKE(Cdecl)      CdeclLambdaPtr(T)        { return &Invoker<T>::Cdecl;      }
template <typename T> PATCHER_INVOKE(Stdcall)    StdcallLambdaPtr(T)      { return &Invoker<T>::Stdcall;    }
template <typename T> PATCHER_INVOKE(Fastcall)   FastcallLambdaPtr(T)     { return &Invoker<T>::Fastcall;   }
template <typename T> PATCHER_INVOKE(Vectorcall) VectorcallLambdaPtr(T)   { return &Invoker<T>::Vectorcall; }
#endif
template <typename T> PATCHER_INVOKE(Thiscall)   ThiscallLambdaPtr(T)     { return &Invoker<T>::Thiscall;   }
template <typename T> PATCHER_INVOKE(Regcall)    RegcallLambdaPtr(T)      { return &Invoker<T>::Regcall;    }
template <typename T> PATCHER_INVOKE(Regparm1)   Regparm1LambdaPtr(T)     { return &Invoker<T>::Regparm1;   }
template <typename T> PATCHER_INVOKE(Regparm2)   Regparm2LambdaPtr(T)     { return &Invoker<T>::Regparm2;   }
template <typename T> PATCHER_INVOKE(Regparm)    RegparmLambdaPtr(T)      { return &Invoker<T>::Regparm;    }
template <typename T> PATCHER_INVOKE(SseRegparm) SseRegparmLambdaPtr(T)   { return &Invoker<T>::SseRegparm; }
///@}


/// @internal Type erasure wrapper for (possibly relocated) uint or void* pointer addresses.
/// If uint, relocation is assumed by default;  if void*, no relocation is assumed by default.
class TargetPtr {
public:
  /// Conversion constructor for plain pointers.  Defaults to not relocated.
  constexpr TargetPtr(void*    pAddress, bool relocate = false) : pAddress_(pAddress), relocate_(relocate) { }

  /// Conversion constructor for raw uint addresses.  Defaults to relocated.
  constexpr TargetPtr(uintptr_t address, bool relocate = true)  :  address_(address),  relocate_(relocate) { }

  /// Conversion constructor for function pointers.  Never relocated.
  template <typename T, typename = EnableIf<std::is_function<RemovePointer<T>>::value>>
  constexpr TargetPtr(T pfnSrcFunction)
    : pAddress_((void*)(pfnSrcFunction)), relocate_(false) { }  // C-style cast due to constexpr quirks.

  /// Conversion operator to void* pointer.
  constexpr operator void*()      const { return pAddress_; }

  /// Conversion operator to uintptr_t.
  constexpr operator uintptr_t()  const { return address_;  }

  /// Returns if the pointer needs to be relocated.
  constexpr bool ShouldRelocate() const { return relocate_; }

private:
  union {
    uintptr_t  address_;
    void*      pAddress_;
  };

  bool  relocate_;
};


/// @internal Type erasure wrapper for const void* function pointers. Can implicitly convert non-capturing lambdas.
class FunctionPtr {
public:
  constexpr FunctionPtr() : pfn_(nullptr) { }

  /// Conversion constructor for plain pointers.
  constexpr FunctionPtr(const void* pSrc) : pfn_(pSrc) { }

  /// Conversion constructor for function pointers.
  template <typename T, typename = EnableIf<std::is_function<RemovePointer<T>>::value>>
  constexpr FunctionPtr(T pfnSrcFunction) : pfn_((void*)(pfnSrcFunction)) { } // C-style cast due to constexpr quirks.

  /// Conversion constructor for non-capturing lambdas, using the build-specified default calling convention.
  template <typename Lambda, typename IsNonCapturingLambda = decltype(LambdaPtr(std::declval<Lambda>()))>
  constexpr FunctionPtr(const Lambda& lambda) : pfn_((void*)LambdaPtr(lambda)) { }

  /// Conversion operator to const void* pointer.
  constexpr operator const void*() const { return pfn_; }

private:
  const void*  pfn_;
};


/// Options passed to PatchContext::LowLevelHook().
namespace LowLevelHookOpt {
enum : uint32 {
  NoBaseRelocReturn  = (1 << 0), ///< Do not automatically adjust custom return destinations for module base relocation.
  NoCustomReturnAddr = (1 << 1), ///< Custom return addresses are not allowed.  Use for hook functions that return void.
  ArgsAsStructPtr    = (1 << 2), ///< Args are passed to the callback as a pointer to a struct that contains them.
};

/// Gets default LowLevelHook options based on the callback function's return type.
template <typename ReturnType>
constexpr uint32 GetDefaults() {
  return ((std::is_pointer<ReturnType>::value ? NoBaseRelocReturn  : 0) |
          (std::is_void<ReturnType>::value    ? NoCustomReturnAddr : 0));
}
}

/// Forward declaration of Register enum class, an array of which is passed to PatchContext::LowLevelHook().
enum class Register : uint8;

/// Transparent wrapper around a type that has a Register enum value attached to it, allowing for deducing the desired
/// register for the arg for LowLevelHook() at compile time.
template <Register Id, typename T>
class RegisterArg {
  using Type     = RemoveReference<T>;
  using Element  = RemovePointer<RemoveAllExtents<Type>>;
  using DataType = Conditional<std::is_array<T>::value, AddLvalueReference<Type>, T>;

  static_assert(std::is_reference<T>::value || std::is_array<T>::value || (sizeof(T) <= sizeof(void*)),
                "Type does not fit in register size.");

public:
  constexpr      Type& Get() { return data_; }

  constexpr operator Type&() { return data_; }

  // In lieu of no "operator.", dereference-like semantics are allowed for all types for shorthand struct field access.
  template <typename U = EnableIf<(std::is_void<Element>::value == false), Element>>
  constexpr U& operator*()  { return Dereference(); }
  template <typename U = Conditional<std::is_pointer<T>::value, T, Element*>>
  constexpr U  operator->() { return data_;  }

  template <typename U>
  Type& operator=(U&&      src) { return (data_ = src); }
  template <typename U>
  Type& operator=(const U& src) { return (data_ = src); }

private:
  template <typename U = EnableIf<(std::is_void<Element>::value == false), Element>>
  constexpr U&        Dereference() { return *data_; }
  template <typename   = EnableIf<((std::is_pointer<T>::value || std::is_array<T>::value) == false)>>
  constexpr DataType& Dereference() { return  data_; }

  DataType  data_;
};

///@{
/// @internal  Helper functions for implementing register type and by reference deduction for LowLevelHook().
template <typename T>  struct GetRegisterArgIdImpl;
template <Register RegId, typename T>
struct GetRegisterArgIdImpl<RegisterArg<RegId, T>> { static constexpr auto Id = RegId; };
template <typename T>
constexpr Register GetRegisterArgId() { return GetRegisterArgIdImpl<RemoveCvRef<RemovePointer<T>>>::Id; }

template <typename... Ts>
constexpr EnableIf<(sizeof...(Ts) == 0), uint32>  MakeByRefMask(uint32 mask = 0, uint32 setMask = 1) { return mask; }
template <typename T, typename... Ts>
constexpr uint32 MakeByRefMask(uint32 mask = 0, uint32 setMask = 1) {
  return MakeByRefMask<Ts...>(
    (mask | ((std::is_pointer<T>::value || std::is_reference<T>::value) ? setMask : 0u)), (setMask << 1));
}
///@}

#if PATCHER_X86_32
/// x86_32 Register types passed to PatchContext::LowLevelHook().
enum class Register : uint8 { Eax = 0, Ecx, Edx, Ebx, Esi, Edi, Ebp, GprLast = Ebp, Esp, Eflags, Count };

///@{
/// Shorthand aliases for RegisterArgs of each x86_32 Register type.  Used for LowLevelHook() hook functions.
template <typename T>  using Eax    = RegisterArg<Register::Eax,    T>;
template <typename T>  using Ecx    = RegisterArg<Register::Ecx,    T>;
template <typename T>  using Edx    = RegisterArg<Register::Edx,    T>;
template <typename T>  using Ebx    = RegisterArg<Register::Ebx,    T>;
template <typename T>  using Esi    = RegisterArg<Register::Esi,    T>;
template <typename T>  using Edi    = RegisterArg<Register::Edi,    T>;
template <typename T>  using Ebp    = RegisterArg<Register::Ebp,    T>;
template <typename T>  using Esp    = RegisterArg<Register::Esp,    T>;
template <typename T>  using Eflags = RegisterArg<Register::Eflags, T>;
///@}
#elif PATCHER_X86_64
/// x86_64 Register types passed to PatchContext::LowLevelHook().
enum class Register : uint8
  { Rax = 0, Rcx, Rdx, Rbx, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rbp, GprLast = Rbp, Rsp, Rflags, Count };

///@{
/// Shorthand aliases for RegisterArgs of each x86_64 Register type.  Used for LowLevelHook() hook functions.
template <typename T>  using Rax    = RegisterArg<Register::Rax,    T>;
template <typename T>  using Rcx    = RegisterArg<Register::Rcx,    T>;
template <typename T>  using Rdx    = RegisterArg<Register::Rdx,    T>;
template <typename T>  using Rbx    = RegisterArg<Register::Rbx,    T>;
template <typename T>  using Rsi    = RegisterArg<Register::Rsi,    T>;
template <typename T>  using Rdi    = RegisterArg<Register::Rdi,    T>;
template <typename T>  using Rbp    = RegisterArg<Register::Rbp,    T>;
template <typename T>  using Rsp    = RegisterArg<Register::Rsp,    T>;
template <typename T>  using R8     = RegisterArg<Register::R8,     T>;
template <typename T>  using R9     = RegisterArg<Register::R9,     T>;
template <typename T>  using R10    = RegisterArg<Register::R10,    T>;
template <typename T>  using R11    = RegisterArg<Register::R11,    T>;
template <typename T>  using R12    = RegisterArg<Register::R12,    T>;
template <typename T>  using R13    = RegisterArg<Register::R13,    T>;
template <typename T>  using R14    = RegisterArg<Register::R14,    T>;
template <typename T>  using R15    = RegisterArg<Register::R15,    T>;
template <typename T>  using Rflags = RegisterArg<Register::Rflags, T>;
///@}
#endif


/// Export insertion/modification info passed to PatchContext::EditExports().
struct ExportInfo {
  /// Constructor for defining an export by symbol name.
  constexpr ExportInfo(void*    pAddress, const char* pSymbolName)
    : type(ByName),  pAddress(pAddress), pSymbolName(pSymbolName) { }
  constexpr ExportInfo(uintptr_t address, const char* pSymbolName)
    : type(ByNameFix), address(address), pSymbolName(pSymbolName) { }

  /// Constructor for defining an export by ordinal.
  constexpr ExportInfo(void*     pAddress, uint16 ordinal) : type(ByOrdinal),  pAddress(pAddress), ordinal(ordinal) { }
  constexpr ExportInfo(uintptr_t address,  uint16 ordinal) : type(ByOrdinalFix), address(address), ordinal(ordinal) { }

  /// Constructor for defining a forwarded export symbol.
  constexpr ExportInfo(const char* pForwardName, const char* pSymbolName)
    : type(Forwarded), pForwardName(pForwardName), pSymbolName(pSymbolName) { }

  enum : uint32 { ByName = 0, ByNameFix, ByOrdinal, ByOrdinalFix, Forwarded }
    type;

  union {
    void*        pAddress;
    uintptr_t    address;
    const char*  pForwardName;
  };

  union {
    const char*  pSymbolName;
    uint16       ordinal;
  };
};


/// Helper function for getting the virtual function table for a given type.  This requires either an object instance,
/// or a "dummy" instance will be attempted to be created if the type is default, move, or copy constructible.
template <typename T>
void** GetVftable(
  const T* pSelf = nullptr)
{
  void** pVftable = nullptr;

  if (std::is_polymorphic<T>::value) {
#if __cpp_if_constexpr
    if ((pSelf == nullptr) || (*reinterpret_cast<void*const*>(pSelf) == nullptr)) {
      using StorageType = AlignedStorage<sizeof(T), alignof(T)>;
      StorageType dummy = { };
      T* pLocalSelf = nullptr;

      if constexpr (std::is_default_constructible_v<T>) {
        pLocalSelf = new(&dummy) T();
      }
      else {
        // If there's no default constructor, we can attempt to use the move or copy constructors if they are available.
        // Warning:  This move/copy construction from a zeroed buffer may be unsafe depending on the implementation!
        StorageType dummy2 = { };

        try {
          if constexpr (std::is_move_constructible_v<T>) {
            pLocalSelf = new(&dummy) T(std::move(reinterpret_cast<T&>(dummy2)));
          }
          else if constexpr (std::is_copy_constructible_v<T>) {
            pLocalSelf = new(&dummy) T(reinterpret_cast<T&>(dummy2));
          }
        }
        catch (...) {
          if constexpr (std::is_destructible_v<T>) {
            pLocalSelf->~T();
          }
          pLocalSelf = nullptr;
        }
      }

      if (pLocalSelf != nullptr) {
        pVftable = *reinterpret_cast<void***>(pLocalSelf);

        if constexpr (std::is_destructible_v<T>) {
          pLocalSelf->~T();
        }
      }
    }
    else
#else
    // Dummy creation logic requires C++17 for if-constexpr.
    assert(pSelf != nullptr);
#endif
    if (pSelf != nullptr) {
      pVftable = *reinterpret_cast<void**const*>(pSelf);
    }
  }

  return pVftable;
}

/// Cast pointer-to-member-function to void*.
/// @note  If not compiling using GCC, For virtual PMFs, an object instance must be passed or class is default, copy,
///        or move constructible.  Class cannot multiply inherit.
/// @see  MFN_PTR() macro, which provides more flexibility for certain compilers and sometimes expands to this function.
template <typename T, typename U>
void* PmfCast(
  U T::*    pmf,
  const T*  pSelf = nullptr)
{
  static_assert(std::is_member_function_pointer<U T::*>::value, "Type requested for PmfCast is a non-PMF type.");
  static constexpr bool HasVftable = std::is_polymorphic<T>::value;

  union {
    U T::*  pmfIn;
    void*   pOut;
    size_t  vftOffset;
  } const cast = { pmf };

  // Non-virtual PMFs are straightforward to convert and do not require an object instance.
  void* pOut = cast.pOut;

  // Test if this is a virtual PMF, which requires special compiler-specific handling.

#if PATCHER_MSVC
  // MSVC generates "vcall" thunks for calling through pointers-to-virtual-member-functions.
  // We have to parse the assembly of the thunk in order to get the offset into the vftable.
# if PATCHER_X86_64
  static constexpr uint8 Vcall[] = { 0x48, 0x8B, 0x01, 0xFF };  // mov rax, [rcx];  jmp qword ptr [rax+?]
# elif PATCHER_X86_32
  static constexpr uint8 Vcall[] = { 0x8B, 0x01, 0xFF };        // mov eax, [ecx];  jmp dword ptr [eax+?]
# else
  static constexpr uint8* Vcall  = nullptr;                     // Unknown architecture.
# endif

  auto*const pOperand = static_cast<uint8*>(PtrInc(cast.pOut, sizeof(Vcall)));

  if (HasVftable && (Vcall != nullptr) && (memcmp(cast.pOut, &Vcall[0], sizeof(Vcall)) == 0) && (*pOperand & 0x20)) {
    // We require an object instance to get the vftable pointer, which is typically initialized during the constructor.
    void**const pVftable = GetVftable(pSelf);

    const size_t offset = (*pOperand == 0x60) ? *(pOperand + 1)                          : // One-byte operand size.
                          (*pOperand == 0xA0) ? *reinterpret_cast<uint32*>(pOperand + 1) : // Dword operand size.
                          0;

    pOut = (pVftable != nullptr) ? pVftable[(offset / sizeof(void*))] : nullptr;
  }
#elif PATCHER_CLANG
  // In the Itanium ABI (used by Clang/GCC/etc. for x86), virtual PMFs have the low bit set to 1.
  if (HasVftable && (cast.vftOffset & 1)) {
    // We require an object instance to get the vftable pointer, which is typically initialized during the constructor.
    void**const pVftable = GetVftable(pSelf);
    pOut = (pVftable != nullptr) ? pVftable[((cast.vftOffset - 1) / sizeof(void*))] : nullptr;
  }
#elif PATCHER_GCC
  // Most GCC-compliant compilers support an extension to cast PMFs to void* to get the raw address, which is ideal.
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wpmf-conversions"
  pOut = (pSelf != nullptr) ? reinterpret_cast<void*>(pSelf->*pmf) : reinterpret_cast<void*>(pmf);
# pragma GCC diagnostic pop
#else
  static_assert(false, "PmfCast is only supported in MSVC, GCC, or Clang.");
#endif

  return pOut;
}

/// Helper macro to get the raw address of a class member function without having an object instance.
/// Usage: Hook(MFN_PTR(ClassA::Function), MFN_PTR(HookClassA::Function));  This takes an identifier, not a PMF.
/// @note  This does not work on overloaded functions.  There may be compiler-specific limitations.
#if PATCHER_MSVC && PATCHER_X86_32
// MSVC (x86_32):  Inline __asm can reference C++ symbols, including virtual methods, by address.
# if (defined(_DEBUG) == false)
#  define MFN_PTR(method) []() { struct { static void* Get() { __asm mov eax, method } } p;  return p.Get(); }()
# else
// Incremental linking (debug) conflicts with this method somewhat and gives you a pointer to a jump thunk instead.
#  define MFN_PTR(method) []() -> void* {                                             \
     struct { static unsigned char* Get() { __asm mov eax, method } } p;              \
     auto*const pfn = p.Get();                                                        \
     return (pfn[0] != 0xE9) ? pfn : (pfn + 5 + *reinterpret_cast<uint32*>(&pfn[1])); \
   }()
# endif
#elif PATCHER_GCC || PATCHER_ICC
// GCC-compliant, ICC:  GCC supports an extension to cast PMFs to void* to get the raw address, which is ideal.
# define MFN_PTR(method) []() {                          \
_Pragma("GCC diagnostic push")                           \
_Pragma("GCC diagnostic ignored \"-Wpmf-conversions\"")  \
    return reinterpret_cast<void*>(&method);             \
_Pragma("GCC diagnostic pop")                            \
  }()
#else
// MSVC (non-x86_32), Clang, other:  See comments of PmfCast about restrictions.
# define MFN_PTR(method) Patcher::PmfCast(&method)
#endif


/// RAII byte array container with a fixed-size initial storage buffer that mallocs on creation if the requested size
/// exceeds the initial size.  Suitable for use in containers.
template <size_t InitialSize>
class ByteArray {
public:
  explicit ByteArray(size_t size);
  ByteArray(const void* pSrc, size_t size);

  template <size_t N>
  ByteArray(const uint8 (&src)[N]) : ByteArray(&src[0], N) { }

  template <size_t N>
  ByteArray(const ByteArray<N>& src) : ByteArray(src.Data(), src.Size()) { }
  template <size_t N>
  ByteArray(ByteArray<N>&& src);

  ~ByteArray() {
    if (pData_ != &localStorage_[0]) {
      free(pData_);
    }
  }

  uint8*       Data()       { return pData_; }
  const uint8* Data() const { return pData_; }

  size_t Size() const { return size_; }

  bool Append(const void* pSrc, size_t size);

private:
  uint8   localStorage_[InitialSize];
  uint8*  pData_;
  size_t  size_;
};

// =====================================================================================================================
template <size_t InitialSize>
ByteArray<InitialSize>::ByteArray(
  size_t size)
  :
  pData_(&localStorage_[0]),
  size_(size)
{
  if (size > sizeof(localStorage_)) {
    // Dynamically allocate storage buffer exceeding InitialSize.
    pData_ = static_cast<uint8*>(malloc(size_));
    if (pData_ != nullptr) {
      memset(pData_, 0, size);
    }
  }
  else {
    memset(&localStorage_[0], 0, sizeof(localStorage_));
  }
}

// =====================================================================================================================
template <size_t InitialSize>
ByteArray<InitialSize>::ByteArray(
  const void*  pSrc,
  size_t       size)
  :
  pData_(&localStorage_[0]),
  size_(size)
{
  assert(pSrc != nullptr);

  if (size > sizeof(localStorage_)) {
    // Dynamically allocate storage buffer exceeding InitialSize.
    pData_ = static_cast<uint8*>(malloc(size_));
  }

  if (pData_) {
    memcpy(pData_, pSrc, size);
  }
}

// =====================================================================================================================
template <size_t InitialSize> template <size_t N>
ByteArray<InitialSize>::ByteArray(
  ByteArray<N>&& src)
  :
  pData_(&localStorage_[0]),
  size_(src.Size())
{
  if (src.pData_ != &src.localStorage_[0]) {
    // Take ownership of the dynamic allocation of the ByteArray we're moving from.
    pData_ = src.pData_;
  }
  else if (src.pData_ != nullptr) {
    if (size_ > sizeof(localStorage_)) {
      // Dynamically allocate storage buffer exceeding InitialSize.
      pData_ = static_cast<uint8*>(malloc(size_));
    }

    if (pData_) {
      memcpy(pData_, src.pData_, size_);
    }
  }
  else {
    pData_ = nullptr;
    size_ = 0;
  }

  src.pData_ = nullptr;
  src.size_ = 0;
}

// =====================================================================================================================
template <size_t InitialSize>
bool ByteArray<InitialSize>::Append(
  const void*  pSrc,
  size_t       size)
{
  bool result = true;

  if ((size + size_) > InitialSize) {
    // Dynamically allocate storage buffer exceeding InitialSize.
    uint8*const pNewData = static_cast<uint8*>(malloc(size + size_));

    if (pNewData != nullptr) {
      memcpy(pNewData, pData_, size_);
      if (pData_ != &localStorage_[0]) {
        free(pData_);
      }
      pData_ = pNewData;
    }
    else {
      result = false;
    }
  }
  if (result == true) {
    memcpy(PtrInc(pData_, size_), pSrc, size);
  }

  return result;
}

} // Patcher
