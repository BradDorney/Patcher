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

#include <type_traits>
#include <tuple>
#include <utility>

#include <cstdint>
#include <cstring>

// Defines

// Compiler/ABI detection
#if (defined(PATCHER_CLANG) || defined(PATCHER_ICC) || defined(PATCHER_GCC) || defined(PATCHER_MSVC)) == false
# if   defined(__clang__) || defined(__INTEL_CLANG_COMPILER)
#  define PATCHER_CLANG  1
# elif defined(__INTEL_COMPILER) || defined(__ICC) || defined(__ICL)
#  define PATCHER_ICC    1
# elif defined(__GNUC__)
#  define PATCHER_GCC    1  // Also matches other GCC-compliant compilers except for Clang and ICC.
# elif defined(_MSC_VER)
#  define PATCHER_MSVC   1
# endif
#endif
#define   PATCHER_GXX    (PATCHER_GCC || PATCHER_CLANG || PATCHER_ICC)

#if (defined(PATCHER_MS_ABI) || defined(PATCHER_UNIX_ABI)) == false
# if defined(_WIN32) || PATCHER_MSVC
#  define PATCHER_MS_ABI    1
# else
#  define PATCHER_UNIX_ABI  1
# endif
#endif

// Architecture detection
#if (defined(PATCHER_X86_32) || defined(PATCHER_X86_64)) == false
# if   defined(_M_IX86) || (defined(__i386__) && (defined(__x86_64__) == false))
#  define PATCHER_X86_32  1
# elif defined(_M_X64) || defined(__x86_64__)
#  define PATCHER_X86_64  1
# endif
#endif
#define   PATCHER_X86     (PATCHER_X86_32 || PATCHER_X86_64)

// Platform-specific headers
#if PATCHER_X86
# include <immintrin.h>
#endif

// Architecture extensions detection
#if defined(PATCHER_X86_SSE_LEVEL) == false
# if   __AVX512F__
#  define  PATCHER_X86_SSE_LEVEL  8                     // AVX512
# elif __AVX2__
#  define  PATCHER_X86_SSE_LEVEL  7                     // AVX2
# elif __AVX__
#  define  PATCHER_X86_SSE_LEVEL  6                     // AVX
# elif __SSE4_2__
#  define  PATCHER_X86_SSE_LEVEL  5                     // SSE4.2
# elif __SSE4_1__
#  define  PATCHER_X86_SSE_LEVEL  4                     // SSE4.1
# elif __SSE3__
#  define  PATCHER_X86_SSE_LEVEL  3                     // SSE3
# elif __SSE2__ || (_M_IX86_FP >= 2) || PATCHER_X86_64
#  define  PATCHER_X86_SSE_LEVEL  2                     // SSE2
# elif __SSE__  || (_M_IX86_FP >= 1)
#  define  PATCHER_X86_SSE_LEVEL  1                     // SSE
# endif
#endif

// Build settings detection
#if PATCHER_MSVC && defined(_DEBUG) && (defined(PATCHER_INCREMENTAL_LINKING) == false)
# define PATCHER_INCREMENTAL_LINKING  1  // MSVC incremental linking is typically on in debug builds and off in release.
#endif

#if ((PATCHER_MSVC && _CPPUNWIND) || (PATCHER_GXX && (__cpp_exceptions || __EXCEPTIONS))) &&  \
    (defined(PATCHER_EXCEPTIONS) == false)
# define PATCHER_EXCEPTIONS  1
#endif

#if PATCHER_EXCEPTIONS
# define PATCHER_UNSAFE_TRY(...)  try { __VA_ARGS__; } catch(...) { }
#else
# define PATCHER_UNSAFE_TRY(...)      { __VA_ARGS__; }
#endif

#if PATCHER_MSVC
# define PATCHER_PRAGMA(expr)                      __pragma(expr)
# define PATCHER_IGNORE_GCC_WARNING(warning, ...)  __VA_ARGS__
#else
# define PATCHER_PRAGMA(expr)                      _Pragma(#expr)
# define PATCHER_IGNORE_GCC_WARNING(warning, ...)  \
  PATCHER_PRAGMA(GCC diagnostic push)              \
  PATCHER_PRAGMA(GCC diagnostic ignored warning)   \
  __VA_ARGS__                                      \
  PATCHER_PRAGMA(GCC diagnostic pop)
#endif

/// Default stack alignment assumed at the beginning of function calls.
#if defined(PATCHER_DEFAULT_STACK_ALIGNMENT) == false
# if PATCHER_X86_64 || PATCHER_UNIX_ABI
#  define PATCHER_DEFAULT_STACK_ALIGNMENT  16
# else
#  define PATCHER_DEFAULT_STACK_ALIGNMENT  RegisterSize
# endif
#endif

/// Size in bytes of the "red zone" below the stack that we can use.
#if defined(PATCHER_STACK_RED_ZONE_SIZE) == false
# if   PATCHER_MS_ABI
#  define PATCHER_STACK_RED_ZONE_SIZE  0
# elif PATCHER_UNIX_ABI
#  define PATCHER_STACK_RED_ZONE_SIZE  128
# endif
#endif

// Calling conventions.  These are ignored if they do not exist for the given target ISA and build config.
#if PATCHER_MSVC || defined(__ICL)
# define  PATCHER_CDECL       __cdecl
# define  PATCHER_STDCALL     __stdcall
# define  PATCHER_FASTCALL    __fastcall
# define  PATCHER_THISCALL    __thiscall
# define  PATCHER_VECTORCALL  __vectorcall
# if defined(__ICL)
#  define PATCHER_REGCALL     __regcall
# else
#  define PATCHER_REGCALL
# endif
# define  PATCHER_REGPARM(n)
# define  PATCHER_SSEREGPARM
# define  PATCHER_MSCALL      __cdecl
# define  PATCHER_UNIXCALL

# define  PATCHER_ATTRIBUTE(attr)
# define  PATCHER_ATTR_PARM(attr, ...)
#elif PATCHER_GXX
# define  PATCHER_CDECL       PATCHER_ATTRIBUTE(__cdecl__)
# define  PATCHER_STDCALL     PATCHER_ATTRIBUTE(__stdcall__)
# define  PATCHER_FASTCALL    PATCHER_ATTRIBUTE(__fastcall__)
# define  PATCHER_THISCALL    PATCHER_ATTRIBUTE(__thiscall__)
# define  PATCHER_VECTORCALL  PATCHER_ATTRIBUTE(__vectorcall__)
# define  PATCHER_REGCALL     PATCHER_ATTRIBUTE(__regcall__)
#if !defined(PATCHER_CLANG)
# define  PATCHER_REGPARM(n)  PATCHER_ATTR_PARM(__regparm__, n)
#else  // ** TODO Fix Clang build errors with regparm in TokenizeFunctionQualifiers
# define  PATCHER_REGPARM(n)
#endif
# define  PATCHER_SSEREGPARM  PATCHER_ATTRIBUTE(__sseregparm__)
# define  PATCHER_MSCALL      PATCHER_ATTRIBUTE(__ms_abi__)
# define  PATCHER_UNIXCALL    PATCHER_ATTRIBUTE(__sysv_abi__)

///@{ @internal  Macro that expands to an attribute if it is defined, otherwise expands to nil.
# define  PATCHER_ATTRIBUTE(attr)        PATCHER_ATTR_IMPL1((__has_attribute(attr), __attribute((attr))))
# define  PATCHER_ATTR_PARM(attr, ...)   PATCHER_ATTR_IMPL1((__has_attribute(attr), __attribute((attr(__VA_ARGS__)))))
///@}

# define  PATCHER_ATTR_IMPL1(args)       PATCHER_ATTR_IMPL2 args
# define  PATCHER_ATTR_IMPL2(has, attr)  PATCHER_ATTR_EXPAND_##has(attr)
# define  PATCHER_ATTR_EXPAND_1(attr)    attr
# define  PATCHER_ATTR_EXPAND_0(attr)
#endif

/// @internal  PATCHER_ABICALL expands to the ABI-specified default calling convention.
#if   PATCHER_X86_32
# define PATCHER_ABICALL  PATCHER_CDECL
#elif PATCHER_MS_ABI
# define PATCHER_ABICALL  PATCHER_MSCALL
#elif PATCHER_UNIX_ABI
# define PATCHER_ABICALL  PATCHER_UNIXCALL
#endif

/// @internal  Macro that takes a macro which takes (convention, name, passthru...) as args, and invokes it for each
///            calling convention.
#if PATCHER_X86_32
# define PATCHER_EMIT_CALLS($, ...)  PATCHER_IGNORE_GCC_WARNING("-Wignored-attributes",               \
  $(PATCHER_CDECL,       Cdecl,       __VA_ARGS__)  $(PATCHER_STDCALL,     Stdcall,     __VA_ARGS__)  \
  $(PATCHER_FASTCALL,    Fastcall,    __VA_ARGS__)  $(PATCHER_THISCALL,    Thiscall,    __VA_ARGS__)  \
  $(PATCHER_VECTORCALL,  Vectorcall,  __VA_ARGS__)  $(PATCHER_REGCALL,     Regcall,     __VA_ARGS__)  \
  $(PATCHER_REGPARM(1),  Regparm1,    __VA_ARGS__)  $(PATCHER_REGPARM(2),  Regparm2,    __VA_ARGS__)  \
  $(PATCHER_REGPARM(3),  Regparm,     __VA_ARGS__)  $(PATCHER_SSEREGPARM,  SseRegparm,  __VA_ARGS__))
#elif PATCHER_X86_64
# define PATCHER_EMIT_CALLS($, ...)  PATCHER_IGNORE_GCC_WARNING("-Wignored-attributes",               \
  $(PATCHER_MSCALL,      Mscall,      __VA_ARGS__)  $(PATCHER_VECTORCALL,  Vectorcall,  __VA_ARGS__)  \
  $(PATCHER_UNIXCALL,    Unixcall,    __VA_ARGS__)  $(PATCHER_REGCALL,     Regcall,     __VA_ARGS__))
#endif

/// @internal  Macro that takes a macro which takes (convention, callName, cv, ref) as args, and invokes it for each
///            combination of calling conventions and qualifiers.
#define PATCHER_EMIT_PMF_QUALIFIERS($)                                                                                 \
  PATCHER_EMIT_CALLS($,,)                 PATCHER_EMIT_CALLS($,,                &)  PATCHER_EMIT_CALLS($,,          &&)\
  PATCHER_EMIT_CALLS($, const,)           PATCHER_EMIT_CALLS($, const,          &)  PATCHER_EMIT_CALLS($, const,    &&)\
  PATCHER_EMIT_CALLS($, volatile,)        PATCHER_EMIT_CALLS($, volatile,       &)  PATCHER_EMIT_CALLS($, volatile, &&)\
  PATCHER_EMIT_CALLS($, const volatile,)  PATCHER_EMIT_CALLS($, const volatile, &)                                     \
  PATCHER_EMIT_CALLS($, const volatile, &&)

/// @internal  Macro that takes a macro which takes (cv, ref) as args, and invokes it for each combination.
#define PATCHER_EMIT_CV_REF_QUALIFIERS($)  $(,)  $(,&)  $(,&&)  $(const,)  $(const, &)  $(const, &&)  \
  $(volatile,)  $(volatile, &)  $(volatile, &&)  $(const volatile,)  $(const volatile, &)  $(const volatile, &&)

namespace Patcher {
// Typedefs

using int8    = int8_t;     ///< 8-bit  signed   integer type.
using int16   = int16_t;    ///< 16-bit signed   integer type.
using int32   = int32_t;    ///< 32-bit signed   integer type.
using int64   = int64_t;    ///< 64-bit signed   integer type.
using uint8   = uint8_t;    ///< 8-bit  unsigned integer type.
using uint16  = uint16_t;   ///< 16-bit unsigned integer type.
using uint32  = uint32_t;   ///< 32-bit unsigned integer type.
using uint64  = uint64_t;   ///< 64-bit unsigned integer type.
using uintptr = uintptr_t;  ///< Pointer-size unsigned integer type.

namespace Registers { enum class Register : uint8; }

// Constants

#if PATCHER_X86_32
constexpr bool IsX86_32 = true;
constexpr bool IsX86_64 = false;
#elif PATCHER_X86_64
constexpr bool IsX86_32 = false;
constexpr bool IsX86_64 = true;
#else
constexpr bool IsX86_32 = false;
constexpr bool IsX86_64 = false;
#endif
constexpr bool IsX86 = IsX86_32 || IsX86_64;

#if PATCHER_MS_ABI
constexpr bool IsMsAbi   = true;
constexpr bool IsUnixAbi = false;
#elif PATCHER_UNIX_ABI
constexpr bool IsMsAbi   = false;
constexpr bool IsUnixAbi = true;
#else
constexpr bool IsMsAbi   = false;
constexpr bool IsUnixAbi = false;
#endif

constexpr size_t RegisterSize = sizeof(void*);  ///< Size in bytes of native registers.

// Utilities

/// Info about registers requested by LowLevelHook().  Can be template deduced.
struct RegisterInfo {
  Registers::Register type;         ///< Register type.
  bool                byReference;  ///< Pass register by reference for writing? (Not needed with stack values)
  uint32              offset;       ///< (Stack only) Offset into the stack associated with this value.
};

namespace Impl {
struct Dummy { explicit constexpr Dummy() { } };  ///< @internal  Empty dummy parameter type.

/// @internal  Returns true if the specified macro is defined to empty. (Cannot be used in preprocessor #if statements.)
#define PATCHER_IS_EMPTY(...)       PATCHER_IS_EMPTY_IMPL(__VA_ARGS__)
#define PATCHER_IS_EMPTY_IMPL(...)  Patcher::Impl::IsMacroEmptyImpl(#__VA_ARGS__)
constexpr bool IsMacroEmptyImpl()            { return true;  }
constexpr bool IsMacroEmptyImpl(const char*) { return false; }
}

/// Enum specifying a function's calling convention.
enum class Call : uint32 {
#define PATCHER_CALLING_CONVENTION_ENUM_DEF(conv, name, ...)  name,
#define PATCHER_DEFAULT_CALLING_CONVENTION_ENUM_DEF(conv, name, ...)                                                   \
  ((PATCHER_IS_EMPTY(conv) == 0) && std::is_same<void(*)(),                void(conv*)()>::value)               ? name :
#define PATCHER_MEMBER_CALLING_CONVENTION_ENUM_DEF(conv, name, ...)                                                    \
  ((PATCHER_IS_EMPTY(conv) == 0) && std::is_same<void(Impl::Dummy::*)(),   void(conv Impl::Dummy::*)()>::value) ? name :
#define PATCHER_ABI_CALLING_CONVENTION_ENUM_DEF(conv, name, ...)                                                       \
  ((PATCHER_IS_EMPTY(conv) == 0) && std::is_same<void(PATCHER_ABICALL*)(), void(conv*)()>::value)               ? name :

  Unknown = 0,
  PATCHER_EMIT_CALLS(PATCHER_CALLING_CONVENTION_ENUM_DEF)
  Count,

  Default  = PATCHER_EMIT_CALLS(PATCHER_DEFAULT_CALLING_CONVENTION_ENUM_DEF) Unknown,
  Member   = PATCHER_EMIT_CALLS(PATCHER_MEMBER_CALLING_CONVENTION_ENUM_DEF)  Unknown,
  AbiStd   = PATCHER_EMIT_CALLS(PATCHER_ABI_CALLING_CONVENTION_ENUM_DEF)     Unknown,
  Variadic = AbiStd,
};


namespace Impl {
namespace CallTraits {
#define PATCHER_SUPPORTED_CALLING_CONVENTION_DEF(conv, name, ...)  (PATCHER_IS_EMPTY(conv) == false),
constexpr bool SupportedCallingConventions[] = { false, PATCHER_EMIT_CALLS(PATCHER_SUPPORTED_CALLING_CONVENTION_DEF) };
constexpr bool Exists(Call convention) { return SupportedCallingConventions[size_t(convention)]; }

enum PropertyFlags : uint32 {
  CalleeCleanup      = (1u << 0),  ///< Callee cleans up the stack allocated for args.  Otherwise assume caller cleanup.
  CalleePopReturnPtr = (1u << 1),  ///< Callee cleans up only the stack allocated for the aggregate return pointer.
  ShadowSpace        = (1u << 2),  ///< Stack is allocated for shadow space for args passed by standard registers.
  AnyTypesInGprs     = (1u << 3),  ///< Any type can be placed in registers.
  PodTypesInGprs     = (1u << 4),  ///< Aligned trivial types, incl. POD class/struct/union, can be placed in registers.
  BigTypesByRef      = (1u << 5),  ///< Arg types larger than 1 register, and unions, are always passed by reference.
  ClassTypesByRef    = (1u << 5),  ///< Non-trivial class/struct/union types are always passed by reference.
  PodTypeGprSplit    = (1u << 6),  ///< Aligned, uniquely-representable, POD types can span multiple registers.
  AnyTypeGprSplit    = (1u << 7),  ///< Any type can span multiple registers.

  IfMsAbi   = IsMsAbi   ? ~0u : 0u,  ///< @internal  Mask for setting properties to only apply when in MS ABI mode.
  IfUnixAbi = IsUnixAbi ? ~0u : 0u   ///< @internal  Mask for setting properties to only apply when in Unix ABI mode.
};

/// @internal  Info about ABI calling conventions.
///
/// For more information, see the following documentation:
/// https://docs.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions
/// https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
/// https://clang.llvm.org/docs/AttributeReference.html
/// https://gcc.gnu.org/onlinedocs/gcc/x86-Function-Attributes.html
/// https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/intel386-psABI-1.1.pdf
/// https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf
/// https://intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/c-c-calling-conventions.html
constexpr struct Traits {
  bool    supported;       ///< Does the compiler and platform support this calling convention?
  uint32  numArgSgprs;     ///< Max number of standard general-purpose registers used for passing args.
  uint32  numReturnSgprs;  ///< Max number of standard general-purpose registers used for passing return value.
  uint32  flags;           ///< Calling convention properties.
} For[size_t(Call::Count)] = {
  {                                                                                                         },
#if PATCHER_X86_32
  { Exists(Call::Cdecl),       0,                    2,  CalleePopReturnPtr & IfUnixAbi                     },
  { Exists(Call::Stdcall),     0,                    2,  CalleeCleanup                                      },
  { Exists(Call::Fastcall),    2,                    2,  CalleeCleanup                                      },
  { Exists(Call::Thiscall),    1,                    2,  CalleeCleanup                                      },
  { Exists(Call::Vectorcall),  2,                    2,  CalleeCleanup                                      },
  { Exists(Call::Regcall),     (IsMsAbi ? 4 : 5),    2,  PodTypesInGprs | PodTypeGprSplit | ClassTypesByRef },
  { Exists(Call::Regparm1),    1,                    2,  PodTypesInGprs | PodTypeGprSplit                   },
  { Exists(Call::Regparm2),    2,                    2,  PodTypesInGprs | PodTypeGprSplit                   },
  { Exists(Call::Regparm),     3,                    2,  PodTypesInGprs | PodTypeGprSplit                   },
  { Exists(Call::SseRegparm),  0,                    2,  CalleePopReturnPtr & IfUnixAbi                     }
#elif PATCHER_X86_64
  { Exists(Call::Mscall),      4,                    1,  ShadowSpace | AnyTypesInGprs | BigTypesByRef       },
  { Exists(Call::Vectorcall),  4,                    1,  ShadowSpace | AnyTypesInGprs | BigTypesByRef       },
  { Exists(Call::Unixcall),    6,                    2,  PodTypesInGprs                                     },
  { Exists(Call::Regcall),     (IsMsAbi ? 11 : 12),  2,  PodTypesInGprs | PodTypeGprSplit | ClassTypesByRef }
#endif
};
}  // CallTraits

constexpr const CallTraits::Traits& GetCallTraits(Call convention) { return CallTraits::For[size_t(convention)]; }
}  // Impl

namespace Util {
///@{ Templated dummy parameter type that can be used to pass a calling convention as a templated function argument.
template <Call C>  struct AsCall{};
#define PATCHER_ASCALL_DEF(conv, name, ...)  constexpr auto As##name = AsCall<Call::name>{};
PATCHER_EMIT_CALLS(PATCHER_ASCALL_DEF);
///@}


///@{ Pointer arithmetic helpers.
template <typename T = void*>        T PtrInc(void*       p, size_t offset) { return T((uint8*)(p)       + offset); }
template <typename T = const void*>  T PtrInc(const void* p, size_t offset) { return T((const uint8*)(p) + offset); }

template <typename T = void*>        T PtrDec(void*       p, size_t offset) { return T((uint8*)(p)       - offset); }
template <typename T = const void*>  T PtrDec(const void* p, size_t offset) { return T((const uint8*)(p) - offset); }

inline size_t PtrDelta(const void* pHigh, const void* pLow)
  { return static_cast<size_t>(static_cast<const uint8*>(pHigh) - static_cast<const uint8*>(pLow)); }

template <typename T = int32>  T PcRelPtr(const void* pFrom, size_t fromSize, const void* pTo)
  { return T(PtrDelta(pTo, PtrInc(pFrom, fromSize))); }  // C-style cast works for both T as integer or pointer type.
template <typename R = int32, typename T>
R PcRelPtr(const T* pFrom, const void* pTo) { return PcRelPtr<R>(pFrom, sizeof(T), pTo); }
///@}

/// Rounds value up to the nearest multiple of align, where align is a power of 2.
template <typename T>
constexpr T Align(T value, size_t align) { return (value + static_cast<T>(align - 1)) & ~static_cast<T>(align - 1); }

/// Returns true if value is at least aligned to the given power-of-two alignment.
template <typename T>
constexpr bool IsAligned(T value, size_t align) { return ((value & static_cast<T>(align - 1)) == 0); }
} // Util


namespace Impl {
///@{ @internal  Returns the sum of the values.  Intended usage is with an expanded non-type parameter pack.
template <typename T = size_t>         constexpr T Sum()                { return 0;                   }
template <typename T, typename... Ts>  constexpr T Sum(T a, Ts... next) { return a + Sum<T>(next...); }
///@}

///@{ @internal  Returns true if any one of the values is truthy, otherwise false.
template <typename T = size_t>         constexpr bool Any()                { return false;                }
template <typename T, typename... Ts>  constexpr bool Any(T a, Ts... next) { return a || Any<T>(next...); }
///@}

///@{ @internal  Returns true if all of the values are truthy, otherwise false.
template <typename T = size_t>         constexpr bool All()                { return false;                }
template <typename T, typename... Ts>  constexpr bool All(T a, Ts... next) { return a && All<T>(next...); }
///@}

///@{ @internal  Type traits convenience aliases.
#if __cpp_lib_is_aggregate
template <typename T>
constexpr bool IsPod() {
  return std::is_trivial_v<T> && std::is_standard_layout_v<T> &&
         (std::is_scalar_v<T> || ((std::is_class_v<T> || std::is_union_v<T>) && std::is_aggregate_v<T>));
}
#else
template <typename T>  constexpr bool IsPod() { return std::is_trivial<T>::value && std::is_standard_layout<T>::value; }
#endif

#if __cpp_lib_has_unique_object_representations
template <typename T>  ///< Requires C++17.  True if T is POD and does not contain alignment padders or floating-points.
constexpr bool IsUniquePod() { return IsPod<T>() && std::has_unique_object_representations<T>::value; }
#else
template <typename T>  constexpr bool IsUniquePod() { return IsPod<T>(); }
#endif

template <typename T>  constexpr bool IsRefPtr() { return std::is_pointer<T>::value || std::is_reference<T>::value; }
template <typename T>  constexpr bool IsDestroyable() { return std::is_destructible<T>::value; }

template <typename T>                using RemovePtr      = typename std::remove_pointer<T>::type;
template <typename T>                using RemoveRef      = typename std::remove_reference<T>::type;
template <typename T>                using RemoveConst    = typename std::remove_const<T>::type;
template <typename T>                using RemoveCv       = typename std::remove_cv<T>::type;
template <typename T>                using RemoveCvRef    = RemoveCv<RemoveRef<T>>;
template <typename T>                using RemoveCvRefPtr = RemoveCvRef<RemovePtr<T>>;
template <typename T>                using RemoveExtent   = typename std::remove_extent<T>::type;
template <typename T>                using RemoveExtents  = typename std::remove_all_extents<T>::type;
template <typename T>                using Decay          = typename std::decay<T>::type;
template <typename T>                using AddPointer     = typename std::add_pointer<T>::type;
template <typename T>                using AddLvalueRef   = typename std::add_lvalue_reference<T>::type;
template <bool B, class T = void>    using EnableIf       = typename std::enable_if<B, T>::type;
template <typename... T>             using ToVoid         = void;
template <bool B, class T, class F>  using Conditional    = typename std::conditional<B, T, F>::type;
template <typename T>                using TypeStorage    = typename std::aligned_storage<sizeof(T), alignof(T)>::type;
template <typename... Ts>            using CommonType     = typename std::common_type<Ts...>::type;
template <typename T, size_t N>      using Array          = T[N];
template <typename T>                using AddPtrIfValue  = Conditional<IsRefPtr<T>(), T, AddPointer<T>>;

template <typename T, bool = std::is_enum<T>::value>  struct UnderlyingTypeImpl { using Type = T; };
template <typename T>  struct UnderlyingTypeImpl<T, true> { using Type = typename std::underlying_type<T>::type; };

template <typename T>  using UnderlyingType = typename UnderlyingTypeImpl<T>::Type;
///@}


/// @internal  Returns the larger of a or b.
template <typename T1, typename T2, typename U = CommonType<T1, T2>>
constexpr U Max(const T1& a, const T2& b) { return (static_cast<U>(a) > static_cast<U>(b)) ? a : b; }

/// @internal  Returns the largest of all the items.
template <typename T1, typename T2, typename U = CommonType<T1, T2>, typename... Ts>
constexpr U Max(const T1& a, const T2& b, const Ts&... rest) { return Max(Max(a, b), rest...); }

/// @internal  Returns the smaller of a or b.
template <typename T1, typename T2, typename U = CommonType<T1, T2>>
constexpr U Min(const T1& a, const T2& b) { return (static_cast<U>(a) < static_cast<U>(b)) ? a : b; }

/// @internal  Returns the smallest of all the items.
template <typename T1, typename T2, typename U = CommonType<T1, T2>, typename... Ts>
constexpr U Min(const T1& a, const T2& b, const Ts&... rest) { return Min(Min(a, b), rest...); }


template <typename T, T... Elements>  struct ValueSequence{};                           ///< Parameter pack of values.
template <size_t... Indices>  using IndexSequence = ValueSequence<size_t, Indices...>;  ///< Parameter pack of size_t.
template <bool... Conditions> using BoolSequence  = ValueSequence<bool, Conditions...>; ///< Parameter pack of bool.
template <typename... Ts>  struct TypeSequence { using Tuple = std::tuple<Ts...>; };    ///< Parameter pack of types.


/// @internal  Gets the length of an array.
template <typename T, size_t N>  constexpr uint32 ArrayLen(const T (&src)[N]) { return static_cast<uint32>(N); }

///@{ @internal  Gets the length of a sequence.
template <typename T, T... Seq>  constexpr size_t SeqSize(ValueSequence<T, Seq...>) { return sizeof...(Seq); }
template <typename... Ts>        constexpr size_t SeqSize(TypeSequence<Ts...>)      { return sizeof...(Ts);  }
///@}


/// @internal  Container for a non-type template argument.
template <typename T, T Value_>
struct ConstValue { static constexpr T Value = Value_;  constexpr operator T() const { return Value; } };

struct NotFound{};  ///< @internal  Empty tag type returned for out-of-bounds TupleElement.

///@{ @internal  TupleElement, gets the Nth element of a std::tuple, TypeSequence, or ValueSequence (as a ConstValue).
template <size_t N, typename T, typename Enable = void>  struct TupleElementImpl { using Type = NotFound; };
template <size_t N, typename T>                          using  TupleElement = typename TupleElementImpl<N, T>::Type;

template <size_t N, typename T>            struct TupleElementImpl<N, T, EnableIf<(N < std::tuple_size<T>::value)>>
  { using Type = typename std::tuple_element<N, T>::type; };

template <size_t N, typename... Ts>        struct TupleElementImpl<N, TypeSequence<Ts...>, void>
  : public TupleElementImpl<N, std::tuple<Ts...>, void>{};

template <size_t N, typename T, T... Seq>  struct TupleElementImpl<N, ValueSequence<T, Seq...>, void>
  : public TupleElementImpl<N, std::tuple<ConstValue<T, Seq>...>, void>{};
///@}


///@{ @internal  ConcatSeq helper metafunction to concatenate N parameter packs of sequences.
template <typename... Seqs>  struct ConcatSeqImpl;
template <typename... Seqs>  using  ConcatSeq = typename ConcatSeqImpl<Seqs...>::Type;

template <typename T, T... Seq>
struct ConcatSeqImpl<ValueSequence<T, Seq...>> { using Type = ValueSequence<T, Seq...>; };

template <typename T, T... SeqA, T... SeqB, typename... Seqs>
struct ConcatSeqImpl<ValueSequence<T, SeqA...>, ValueSequence<T, SeqB...>, Seqs...>
  { using Type = ConcatSeq<ValueSequence<T, SeqA..., SeqB...>, Seqs...>; };

template <typename... Seq>
struct ConcatSeqImpl<TypeSequence<Seq...>> { using Type = TypeSequence<Seq...>; };

template <typename... SeqA, typename... SeqB, typename... Seqs>
struct ConcatSeqImpl<TypeSequence<SeqA...>, TypeSequence<SeqB...>, Seqs...>
  { using Type = ConcatSeq<TypeSequence<SeqA..., SeqB...>, Seqs...>; };
///@}


///@{ @internal  Helper metafunctions to generate parameter packs of sequences.
template <typename T, T Begin, size_t Length>  struct MakeSeqRangeImpl;
template <typename T, T Begin, size_t Length>  using MakeSeqRange = typename MakeSeqRangeImpl<T, Begin, Length>::Type;

template <typename T, T Begin>        struct MakeSeqRangeImpl<T, Begin, 0> { using Type = ValueSequence<T>;        };
template <typename T, T Begin>        struct MakeSeqRangeImpl<T, Begin, 1> { using Type = ValueSequence<T, Begin>; };
template <typename T, T B, size_t L>  struct MakeSeqRangeImpl
  { using Type = ConcatSeq<MakeSeqRange<T, B, (L/2)>, MakeSeqRange<T, B + (L/2), L - (L/2)>>; };

template <typename Seq, typename T>  struct MakeTypeSeqImpl;
template <size_t, typename T>        using  IndexToType = T;
template <typename T, size_t... Is>
struct MakeTypeSeqImpl<IndexSequence<Is...>, T> { using Type = TypeSequence<IndexToType<Is, T>...>; };
///@}

/// @internal  Makes an IndexSequence from [0..Length).
template <size_t Length>             using MakeIndexSequence = MakeSeqRange<size_t, 0, Length>;
/// @internal  Makes an IndexSequence from [Begin..End).
template <size_t Begin, size_t End>  using MakeIndexRange    = MakeSeqRange<size_t, Begin, (End - Begin)>;
/// @internal  Makes a homogenous TypeSequence of Length elements.
template <typename T, size_t Length>
using MakeTypeSequence = typename MakeTypeSeqImpl<MakeIndexSequence<Length>, T>::Type;

///@{ @internal  SliceSeq/SeqElements helper metafunctions to obtain a subsequence from a sequence.
template <typename Seq, typename Is>  struct SliceSeqImpl;

template <typename... Seq, size_t... Is>
struct SliceSeqImpl<TypeSequence<Seq...>, IndexSequence<Is...>> {
  using Parent = TypeSequence<Seq...>;
  using Type   = TypeSequence<TupleElement<Is, Parent>...>;
};

template <typename T, T... Seq, size_t... Is>
struct SliceSeqImpl<ValueSequence<T, Seq...>, IndexSequence<Is...>> {
  using Parent = ValueSequence<T, Seq...>;
  using Type   = ValueSequence<T, TupleElement<Is, Parent>::Value...>;
};

template <typename T, size_t Begin, size_t End = SeqSize(T{})>
using SliceSeq = typename SliceSeqImpl<T, MakeIndexRange<Min(Begin, SeqSize(T{})), Min(End, SeqSize(T{}))>>::Type;
template <typename Seq, typename Is>  using SeqElements = typename SliceSeqImpl<Seq, Is>::Type;
///@}

///@{ @internal  FilterSeq/FilterFalseSeq helper metafunctions to obtain a subsequence from Seq filtered by Conditions.
template <template<class, class> class Filter, typename Seq, typename Conditions>
using FilterHelper = SeqElements<Seq, typename Filter<MakeIndexSequence<SeqSize(Seq{})>, Conditions>::Type>;

template <typename Seq, typename Conditions>  struct FilterSeqImpl;
template <typename Seq, typename Conditions>  struct FilterFalseSeqImpl;
template <typename Seq, typename Conditions>  using  FilterSeq      = FilterHelper<FilterSeqImpl,      Seq, Conditions>;
template <typename Seq, typename Conditions>  using  FilterFalseSeq = FilterHelper<FilterFalseSeqImpl, Seq, Conditions>;

template <size_t... Indexes, bool... Conditions>
struct FilterSeqImpl<IndexSequence<Indexes...>,      BoolSequence<Conditions...>>
  { using Type = ConcatSeq<IndexSequence<>, Conditional<Conditions, IndexSequence<Indexes>, IndexSequence<>>...>; };

template <size_t... Indexes, bool... Conditions>
struct FilterFalseSeqImpl<IndexSequence<Indexes...>, BoolSequence<Conditions...>>
  { using Type = ConcatSeq<IndexSequence<>, Conditional<Conditions, IndexSequence<>, IndexSequence<Indexes>>...>; };
///@}

/// @internal  Gets the median element of a value sequence as a ConstValue (or NotFound if empty sequence).
template <typename T, T... Seq>  using SeqMedian = TupleElement<(sizeof...(Seq) / 2), ValueSequence<T, Seq...>>;

/// @internal  Functor that returns -1 if (a < b), 0 if (a == b), or 1 if (a > b).  For use with SeqSort.
struct Less {
  template <typename T>
  constexpr int32 operator()(const T& a, const T& b) const { return (a < b) ? -1 : ((a == b) ? 0 : 1); }

  template <typename T, T A, T B>
  constexpr int32 operator()(ConstValue<T, A>, ConstValue<T, B>) const { return operator()(A, B); }
};

/// @internal  Template functor that does a proxy comparison using a reference key sequence.  For use with SeqSort.
template <typename Seq, typename Compare = Less>
struct KeySeqCompare {
  template <size_t A, size_t B>  constexpr int32 operator()(ConstValue<size_t, A>, ConstValue<size_t, B>) const
    { return Compare{}(TupleElement<A, Seq>{}, TupleElement<B, Seq>{}); }
};

///@{ @internal  SeqBinSearch helper metafunction to do a binary search over a ValueSequence at compile time.
///   Returns the index of the element if found, otherwise returns ~0 if not found.
///   Sequence must be sorted in ascending order.
template <typename Seq, typename Key, typename Enable = void>
struct SeqBinSearchImpl { using Type = ConstValue<size_t, ~0u>; };  // Key not found.

template <typename T, T Key, T... Seq>
struct SeqBinSearchImpl<ValueSequence<T, Seq...>, ConstValue<T, Key>, EnableIf<(SeqMedian<T, Seq...>::Value == Key)>>
  { using Type = ConstValue<size_t, (sizeof...(Seq) / 2)>; };       // Key found.  Return its element index.

template <typename T, T Key, T... Seq>
struct SeqBinSearchImpl<ValueSequence<T, Seq...>, ConstValue<T, Key>, EnableIf<(SeqMedian<T, Seq...>::Value >  Key)>> {
  using LowerHalf = SliceSeq<ValueSequence<T, Seq...>, 0, (sizeof...(Seq) / 2)>;
  using Type      = typename SeqBinSearchImpl<LowerHalf, ConstValue<T, Key>>::Type;  // Recurse down lower half.
};

template <typename T, T Key, T... Seq>
struct SeqBinSearchImpl<ValueSequence<T, Seq...>, ConstValue<T, Key>, EnableIf<(SeqMedian<T, Seq...>::Value <  Key)>> {
  using UpperHalf = SliceSeq<ValueSequence<T, Seq...>, ((sizeof...(Seq) / 2) + 1)>;  // +1 to exclude middle element
  using Type      = typename SeqBinSearchImpl<UpperHalf, ConstValue<T, Key>>::Type;  // Recurse down upper half.
};

template <typename T, T Key, T... Seq>
using SeqBinSearchResult = typename SeqBinSearchImpl<ValueSequence<T, Seq...>, ConstValue<T, Key>>::Type;

template <typename T, T Key, T... Is>  constexpr size_t SeqBinSearch(ValueSequence<T, Is...>, ConstValue<T, Key>)
  { return SeqBinSearchResult<T, Key, Is...>::Value; }

template <typename T, T Key, T... Is>  constexpr size_t SeqBinSearch() { return SeqBinSearch<T, Key, Is...>({}, {}); }
///@}

///@{ @internal  SpliceSeq helper to get a subset of Seq that filters out elements present in Exclude (must be sorted).
template <typename Seq, typename Exclude>  struct SpliceSeqImpl;
template <typename Seq, typename Exclude>  using  SpliceSeq = typename SpliceSeqImpl<Seq, Exclude>::Type;

template <typename T, T... Seq, T... Exclude>
struct SpliceSeqImpl<ValueSequence<T, Seq...>, ValueSequence<T, Exclude...>> {
  template <typename U, U I>  // Note: We cannot just declare I as type T due to a MSVC 2017 build error.
  static constexpr bool IsExcluded() { return SeqBinSearch(ValueSequence<T, Exclude...>{}, ConstValue<U, I>{}) != ~0u; }

  using Type = FilterFalseSeq<ValueSequence<T, Seq...>, BoolSequence<IsExcluded<T, Seq>()...>>;
};
///@}

///@{ @internal  SeqSort helper metafunction to sort a ValueSequence.
template <typename Seq, typename Compare>         struct SeqSortImpl;
template <typename Seq, typename Compare = Less>  using  SeqSort = typename SeqSortImpl<Seq, Compare>::Type;

template <typename SeqA, typename SeqB, typename Compare, typename Enable = void>  struct SeqMergeSortImpl;
template <typename SeqA, typename SeqB, typename Compare = Less>
using SeqMergeSort = typename SeqMergeSortImpl<SeqA, SeqB, Compare>::Type;

template <typename T, typename Compare>
struct SeqMergeSortImpl<ValueSequence<T>, ValueSequence<T>, Compare, void>
  { using Type = ValueSequence<T>; };           // Terminate upon reaching the end of both subsequences.

template <typename T, typename Compare, T... SeqA>
struct SeqMergeSortImpl<ValueSequence<T, SeqA...>, ValueSequence<T>, Compare, void>
  { using Type = ValueSequence<T, SeqA...>; };  // Terminate upon reaching the end of SeqB.

template <typename T, typename Compare, T... SeqB>
struct SeqMergeSortImpl<ValueSequence<T>, ValueSequence<T, SeqB...>, Compare, void>
  { using Type = ValueSequence<T, SeqB...>; };  // Terminate upon reaching the end of SeqA.

template <typename T, typename Compare, T A, T B, T... SeqA, T... SeqB>
struct SeqMergeSortImpl<ValueSequence<T, A, SeqA...>, ValueSequence<T, B, SeqB...>, Compare,
  EnableIf<(Compare{}(ConstValue<T, A>{}, ConstValue<T, B>{}) <= 0)>>
{
  using Type =  // Pop front of SeqA into the sorted sequence, and then continue.
    ConcatSeq<ValueSequence<T, A>, SeqMergeSort<ValueSequence<T, SeqA...>, ValueSequence<T, B, SeqB...>, Compare>>;
};

template <typename T, typename Compare, T A, T B, T... SeqA, T... SeqB>
struct SeqMergeSortImpl<ValueSequence<T, A, SeqA...>, ValueSequence<T, B, SeqB...>, Compare,
  EnableIf<(Compare{}(ConstValue<T, A>{}, ConstValue<T, B>{}) > 0)>>
{
  using Type =  // Pop front of SeqB into the sorted sequence, and then continue.
    ConcatSeq<ValueSequence<T, B>, SeqMergeSort<ValueSequence<T, A, SeqA...>, ValueSequence<T, SeqB...>, Compare>>;
};

template <typename T, typename Compare>             // Terminate upon reaching an empty slice.
struct SeqSortImpl<ValueSequence<T>, Compare> { using Type = ValueSequence<T>; };

template <typename T, typename Compare, T Element>  // Terminate upon reaching a singleton slice.
struct SeqSortImpl<ValueSequence<T, Element>, Compare> { using Type = ValueSequence<T, Element>; };

template <typename T, typename Compare, T... Seq>   // Recursively slice sequence in half and merge sort.
struct SeqSortImpl<ValueSequence<T, Seq...>, Compare> {
  using LowerHalf = SliceSeq<ValueSequence<T, Seq...>, 0, (sizeof...(Seq) / 2)>;
  using UpperHalf = SliceSeq<ValueSequence<T, Seq...>,    (sizeof...(Seq) / 2)>;
  using Type      = SeqMergeSort<SeqSort<LowerHalf, Compare>, SeqSort<UpperHalf, Compare>, Compare>;
};
///@}


/// @internal  Transparent wrapper around a type, as if it were passed as a function argument.
/// @note      Depending on the platform ABI, like in MSVC x86-32, ArgWrappers might be never passed via registers.
template <typename T>
class ArgWrapper {
  using Type      = RemoveRef<T>;
  using Element   = Conditional<std::is_array<T>::value, RemoveExtent<Type>, RemovePtr<Type>>;
  using Reference = Conditional<std::is_rvalue_reference<T>::value, Type&&, Type&>;
  using DataType  = Conditional<std::is_array<T>::value, Type&, T>;

public:
  ArgWrapper() = default;                                                                ///< Inherit any default ctor.
  template <typename U = Type>    ArgWrapper(U&& src) : data_(std::forward<U>(src)) { }  ///< Implicit conversion ctor.
  template <typename U>  Reference operator=(U&& src) { return (data_ = std::forward<U>(src)); }  ///< Assignment.

  Reference Get()      { return data_; } ///< Explicitly retrieves the underlying data.
  operator Reference() { return data_; } ///< Implicit conversion operator to a reference of the underlying type.

  AddPointer<Type> operator&() { return &data_; }  ///< Reference operator.

  ///@{ In lieu of no "operator.", dereference-like semantics are allowed for all types for struct field access, etc.
  template <typename U = Element> auto operator->() -> EnableIf<std::is_same<U, Type>::value,     U*> { return &data_; }
  template <typename U = Element> auto operator->() -> EnableIf<std::is_same<U, Type>::value ==0, U*> { return  data_; }
  template <typename U = Element> auto operator*()  -> EnableIf<std::is_same<U, Type>::value ==0, U&> { return *data_; }
  template <typename U = Element> auto operator*()  -> EnableIf<std::is_same<U, Type>::value,     U&> { return  data_; }
  ///@}

private:
  DataType data_;
};

/// @internal  Tag wrapper type to allow certain FuncSig info to be preserved when round-tripped from FuncSig <-> Pfn.
template <typename R>
class ReturnTag : public ArgWrapper<R> { public:  using ArgWrapper<R>::ArgWrapper;  using ArgWrapper<R>::operator=; };

/// @internal  Converts a type to its effective machine representation when passed as a function arg.
template <typename T> using EffectiveArgType = Decay<Conditional<std::is_reference<T>::value, Decay<T>*, T>>;

/// @internal  Returns sizeof(T), except void and empty types always return 0.
template <typename T, bool Empty = (std::is_void<T>::value || std::is_empty<T>::value)>
constexpr size_t SizeOfType() { return Empty ? 0 : sizeof(Conditional<Empty, int, T>); }

/// @internal  Returns true if args of the given type would be passed by reference.
template <typename T, Call C = Call::Default, typename Arg = EffectiveArgType<T>, uint32 Flags = GetCallTraits(C).flags>
constexpr bool IsArgByRef() {
  return ((Flags  & CallTraits::ClassTypesByRef) && std::is_class<Arg>::value && (IsPod<Arg>() == false)) ||
          ((Flags & CallTraits::BigTypesByRef)   && ((SizeOfType<Arg>() > RegisterSize) || std::is_union<Arg>::value));
}

/// @internal  Gets a type's aligned size when passed as a function argument.
template <typename T, Call C = Call::Default>  constexpr size_t ArgSize()
  { return IsArgByRef<T, C>() ? RegisterSize : Util::Align(SizeOfType<EffectiveArgType<T>>(), RegisterSize); }

/// @internal  Gets the overall stack alignment required for a function's argument types.
template <typename... Args>  constexpr size_t GetStackAlignment()
  { return Max(RegisterSize, PATCHER_DEFAULT_STACK_ALIGNMENT, alignof(EffectiveArgType<Args>)...); }

/// @internal  Type sequence containing all intrinsic vector types.
using IntrinsicVectorTypes = TypeSequence<
#if PATCHER_X86
  __m64                           // MMX
# if PATCHER_X86_SSE_LEVEL >= 1
  , __m128, __m128d, __m128i      // SSE1 - SSE4.2
# endif
# if PATCHER_X86_SSE_LEVEL >= 6
  , __m256, __m256d               // AVX
# endif
# if PATCHER_X86_SSE_LEVEL >= 7
  , __m256i                       // AVX2
# endif
# if PATCHER_X86_SSE_LEVEL >= 8
  , __m512,   __m512d,  __m512i,  // AVX512
    __m128bh, __m256bh, __m512bh
# endif
#endif
>;

///@{ @internal  Returns true if T is a floating-point or intrinsic vector type.
template <typename T, typename... VectorTypes>  constexpr bool IsVectorArg(TypeSequence<VectorTypes...>)
  { return Any(std::is_floating_point<T>::value, std::is_same<T, VectorTypes>::value...); }

template <typename T>  constexpr bool IsVectorArg() { return IsVectorArg<T>(IntrinsicVectorTypes{}); }
///@}

/// @internal  Returns true if T would be returned via aggregate-return pointer (a hidden parameter).
template <typename T, Call C = Call::Default>
constexpr bool IsAggregateReturnArg() {
  return (std::is_void<T>::value == false) && (std::is_empty<T>::value == false) &&
    ((std::is_trivial<T>::value == false) || (SizeOfType<T>() > (RegisterSize * GetCallTraits(C).numReturnSgprs)));
}

///@{ @internal  Template aliases that expand to void if the specified calling convention exists, else to a dummy type.
template <Call C>  using EnableIfConventionExists = Conditional<GetCallTraits(C).supported, void, Util::AsCall<C>>;
///@}

///@{ @internal  Implementation for helper template which breaks out qualifiers from a function pointer.
template <typename T, typename = void>  struct TokenizeFunctionQualifiersImpl;
template <typename R, typename... A>
struct TokenizeFunctionQualifiersImpl<R(*)(A..., ...), void> {
  static constexpr auto Convention = Call::Variadic;
  using StripAll                   = R(A..., ...);
  using StripConvention            = R(*)(A..., ...);
};

#define PATCHER_TOKENIZE_FUNCTION_QUALIFIERS_DEF(conv, name, ...)                                         \
template <typename R, typename... A>                                                                      \
struct TokenizeFunctionQualifiersImpl<R(conv*)(A...), EnableIfConventionExists<Call::name>> {             \
  static constexpr auto Convention = Call::name;                                                          \
  using StripAll                   = R(A...);                                                             \
  using StripConvention            = R(*)(A...);                                                          \
};

#define PATCHER_TOKENIZE_PMF_QUALIFIERS_DEF(conv, name, cv, ref, ...)                                     \
template <typename T, typename R, typename... A>                                                          \
struct TokenizeFunctionQualifiersImpl<R(conv T::*)(A...) cv ref, EnableIfConventionExists<Call::name>> {  \
  static constexpr auto Convention = Call::name;                                                          \
  using This                       = AddPtrIfValue<cv T ref>;                                             \
  using StripAll                   = R (T::*)(A...);                                                      \
  using StripConvention            = R (T::*)(A...) cv ref;                                               \
  using StripThisQualifiers        = R (conv T::*)(A...);                                                 \
};

#define PATCHER_TOKENIZE_VARIADIC_PMF_QUALIFIERS_DEF(cv, ref, ...)                                        \
template <typename T, typename R, typename... A>                                                          \
struct TokenizeFunctionQualifiersImpl<R(T::*)(A..., ...) cv ref, void> {                                  \
  static constexpr auto Convention = Call::Variadic;                                                      \
  using This                       = AddPtrIfValue<cv T ref>;                                             \
  using StripAll                   = R (T::*)(A..., ...);                                                 \
  using StripConvention            = R (T::*)(A..., ...) cv ref;                                          \
  using StripThisQualifiers        = R (T::*)(A..., ...);                                                 \
};

PATCHER_EMIT_CALLS(PATCHER_TOKENIZE_FUNCTION_QUALIFIERS_DEF);
PATCHER_EMIT_PMF_QUALIFIERS(PATCHER_TOKENIZE_PMF_QUALIFIERS_DEF);
PATCHER_EMIT_CV_REF_QUALIFIERS(PATCHER_TOKENIZE_VARIADIC_PMF_QUALIFIERS_DEF);
///@}

///@{ @internal  Helper template aliases that strip qualifiers from a function, for simplifying template matching.
// ** TODO Replace most uses of PATCHER_EMIT_CALLS/PATCHER_EMIT_PMF_QUALIFIERS/PATCHER_EMIT_CV_REF_QUALIFIERS with this?
template <typename T>  using TokenizeFunctionQualifiers = TokenizeFunctionQualifiersImpl<Decay<T>>;
template <typename T>  using StripAllFunctionQualifiers = typename TokenizeFunctionQualifiers<T>::StripAll;
template <typename T>  using StripConvention            = typename TokenizeFunctionQualifiers<T>::StripConvention;
///@}

///@{ @internal  AddConvention helper to convert function types to function pointers of other calling conventions.
template <typename T, Call C>  struct AddConventionImpl{};
template <typename T, Call C>  using  AddConvention = typename AddConventionImpl<StripConvention<T>, C>::Type;

template <typename R, typename... A, Call C>
struct AddConventionImpl<R(*)(A..., ...),           C>          { using Type = R(*)(A..., ...);           };

#define PATCHER_ADD_CONVENTION_DEF(conv, name, ...)                                                        \
template <typename R, typename... A>                                                                       \
struct AddConventionImpl<R(*)(A...),                Call::name> { using Type = R(conv*)(A...);            };

#define PATCHER_ADD_CONVENTION_PMF_DEF(conv, name, cv, ref, ...)                                           \
template <typename T, typename R, typename... A>                                                           \
struct AddConventionImpl<R(T::*)(A...) cv ref,      Call::name> { using Type = R(conv T::*)(A...) cv ref; };

#define PATCHER_ADD_CONVENTION_PMF_VARIADIC_DEF(cv, ref)                                                   \
template <typename T, typename R, typename... A, Call C>                                                   \
struct AddConventionImpl<R(T::*)(A..., ...) cv ref, C>          { using Type = R(T::*)(A..., ...) cv ref; };

PATCHER_ADD_CONVENTION_DEF(, Unknown);
PATCHER_EMIT_CALLS(PATCHER_ADD_CONVENTION_DEF);
PATCHER_EMIT_PMF_QUALIFIERS(PATCHER_ADD_CONVENTION_PMF_DEF);
PATCHER_EMIT_CV_REF_QUALIFIERS(PATCHER_ADD_CONVENTION_PMF_VARIADIC_DEF);
///@}

///@{ @internal  MakeVariadic helper to add a "..." parameter to an unqualified function type.
template <typename T>                 struct MakeVariadicImpl          { using Type = T;            };
template <typename R, typename... A>  struct MakeVariadicImpl<R(A...)> { using Type = R(A..., ...); };
template <typename T>  using MakeVariadic = typename MakeVariadicImpl<T>::Type;
///@}

///@{ @internal  GetParams helper to extract the parameters from an unqualified function type as a TypeSequence.
template <typename T>                 struct GetParamsImpl               { using Type = TypeSequence<>;     };
template <typename R, typename... A>  struct GetParamsImpl<R(A...)>      { using Type = TypeSequence<A...>; };
template <typename R, typename... A>  struct GetParamsImpl<R(A..., ...)> { using Type = TypeSequence<A...>; };
template <typename T>  using GetParams = typename GetParamsImpl<T>::Type;
///@}


///@{ @internal  Template metafunction used to obtain function call signature information from a callable.
template <typename T, typename = void>  struct FuncTraitsImpl   :   public FuncTraitsImpl<decltype(&T::operator())>{};
template <typename T>                   using  FuncTraits       = typename FuncTraitsImpl<Decay<T>>::Type;
template <typename T>                   using  FuncTraitsNoThis = typename FuncTraits<T>::StripThis;
///@}

///@{ @internal  Template that defines typed function call signature information for use at compile time.
// ** TODO In Unix x86-32, if (HasThisPtr && HasReturnPtr), Pfn isn't able to handle cdecl callee pop return ptr
template <typename R, Call Call = Call::Default, bool Variadic = false, typename This = void, typename... A>
struct FuncSig {
  static constexpr bool HasThisPtr   = (std::is_void<This>::value == false);  ///< Has "this" parameter?
  static constexpr bool HasReturnPtr = IsAggregateReturnArg<R, Call>();       ///< Uses aggregate return?
  static constexpr bool IsVariadic   = Variadic;                              ///< Is function variadic?

  static constexpr size_t NumParams  = sizeof...(A);  ///< Number of non-implicit function params.
  static constexpr auto   Convention = Call;          ///< Calling convention.

  static constexpr size_t ReturnSize                        = SizeOfType<R>();           ///< Size of return type.
  static constexpr size_t ParamSizes[Max(NumParams, 1u)]    = { ArgSize<A>()...     };   ///< Aligned sizes of params.
  static constexpr bool   ParamIsVector[Max(NumParams, 1u)] = { IsVectorArg<A>()... };   ///< Are params float/vector?
  static constexpr size_t TotalParamSize                    = Sum(ArgSize<A>()...);      ///< Total aligned params size.
  static constexpr size_t StackAlignment                    = GetStackAlignment<A...>(); ///< Stack alignment for args.

  using ThisPtr   = AddPtrIfValue<This>;  ///< "this" qualified parameter type.
  using ReturnPtr = AddPtrIfValue<R>;     ///< Return pointer parameter type.

  using FnBase_ = Conditional<(HasThisPtr && HasReturnPtr),  ReturnPtr(ThisPtr, ReturnTag<R>&, A...),
                  Conditional<HasThisPtr,                    R(ThisPtr, A...),  R(A...)>>;

  using Function  = Conditional<Variadic, MakeVariadic<FnBase_>, FnBase_>;   ///< Unqualified function signature.
  using Pfn       = AddConvention<Function, Call>;                           ///< Qualified function pointer signature.
  using Return    = Conditional<(HasThisPtr && HasReturnPtr), ReturnPtr, R>; ///< Implicit function return type.
  using Result    = R;                                                       ///< Explicit function return type.
  using Params    = TypeSequence<A...>;                                      ///< Non-implicit params as a TypeSequence.
  using AllParams = GetParams<Function>;                                     ///< All params including implicit ones.
  template <size_t N>  using Param = TupleElement<N, Params>;                ///< Nth parameter's type.

  /// Returns a FuncSig with the "this" (first) parameter removed.
  using StripThis = Conditional<HasThisPtr, FuncSig<R, Call::Unknown, Variadic, void, A...>, FuncSig>;
};

template <typename RetnPtr, Call C, bool V, typename ThisPtr, typename R, typename... A>
struct FuncSig<RetnPtr, C, V, void, ThisPtr, ReturnTag<R>&, A...> : public FuncSig<R, C, V, RemovePtr<ThisPtr>, A...>{};
///@}

/// @internal  Defines untyped function call signature information for use at runtime.
struct DynFuncSig {
  /// Conversion constructor for the compile-time counterpart to this type, FuncSig.
  template <typename R, Call C, bool V, typename... A>
  constexpr DynFuncSig(FuncSig<R, C, V, A...> x)
    : convention(C),
      returnSize(decltype(x)::ReturnSize),
      numParams(decltype(x)::NumParams),
      pParamSizes(&decltype(x)::ParamSizes[0]),
      pParamIsVector(&decltype(x)::ParamIsVector[0]),
      totalParamSize(decltype(x)::TotalParamSize),
      stackAlignment(decltype(x)::StackAlignment),
      hasThisPtr(decltype(x)::HasThisPtr),
      hasReturnPtr(decltype(x)::HasReturnPtr),
      isVariadic(V),
      reserved() { }

  /// Default constructor with unspecified call signature information.
  constexpr DynFuncSig()
    : convention(), returnSize(), numParams(), pParamSizes(), pParamIsVector(), totalParamSize(), stackAlignment(),
      hasThisPtr(), hasReturnPtr(), isVariadic(), reserved() { }

  Call           convention;      ///< Function calling convention.
  size_t         returnSize;      ///< Size in bytes of the function's returned value.
  size_t         numParams;       ///< Number of non-implicit parameters to call the function.
  const size_t*  pParamSizes;     ///< Aligned size in bytes of each parameter.
  const bool*    pParamIsVector;  ///< Specifies whether each parameter is floating-point/intrinsic vector type.
  size_t         totalParamSize;  ///< Total size in bytes of all @ref numParams parameters and alignment padding.
  size_t         stackAlignment;  ///< Stack alignment requirement upon entering the function.

  uint32 hasThisPtr   :  1;  ///< "this" parameter is present.
  uint32 hasReturnPtr :  1;  ///< Return value is handled by aggregate-return.
  uint32 isVariadic   :  1;  ///< Function takes a dynamic variable number of arguments.
  uint32 reserved     : 29;  ///< Reserved for future use.
};

///@{ @internal  FuncTraitsImpl template metafunction used to obtain function call signature information from a callable
#define PATCHER_FUNC_TRAITS_DEF(conv, name, ...)                                        \
template <typename R, typename... A>                                                    \
struct FuncTraitsImpl<R(conv*)(A...), EnableIfConventionExists<Call::name>>             \
  { using Type = FuncSig<R, Call::name, false, void, A...>; };

#define PATCHER_FUNC_TRAITS_PMF_DEF(conv, name, cv, ref, ...)                           \
template <typename R, typename T, typename... A>                                        \
struct FuncTraitsImpl<R(conv T::*)(A...) cv ref, EnableIfConventionExists<Call::name>>  \
  { using Type = FuncSig<R, Call::name, false, cv T ref, A...>; };

#define PATCHER_FUNC_TRAITS_VARIADIC_PMF_DEF(cv, ref)                                   \
template <typename R, typename T, typename... A>                                        \
struct FuncTraitsImpl<R(T::*)(A..., ...) cv ref, void>                                  \
  { using Type = FuncSig<R, Call::Variadic, true, cv T ref, A...>; };

template <typename R, typename... A>
struct FuncTraitsImpl<R(*)(A..., ...)> { using Type = FuncSig<R, Call::Variadic, true, void, A...>; };

PATCHER_EMIT_CALLS(PATCHER_FUNC_TRAITS_DEF);
PATCHER_EMIT_PMF_QUALIFIERS(PATCHER_FUNC_TRAITS_PMF_DEF);
PATCHER_EMIT_CV_REF_QUALIFIERS(PATCHER_FUNC_TRAITS_VARIADIC_PMF_DEF);
///@}


///@{ @internal  Helper template used in converting non-capturing lambdas (and stateless functors) to function pointers.
template <typename T, bool Empty>  struct LambdaInvokerImpl{};
template <typename T>
using LambdaInvoker = LambdaInvokerImpl<StripAllFunctionQualifiers<decltype(&T::operator())>, std::is_empty<T>::value>;

template <typename Lambda, typename Return, typename... Args>
struct LambdaInvokerImpl<Return(Lambda::*)(Args...), true> {
  static constexpr Lambda* GetInvoker() { return nullptr; }
  template <Call C>  struct As{};

#define PATCHER_LAMBDA_INVOKER_CONVERSION_DEF(convention, name, ...)                                 \
  template <>  struct As<Call::name>                                                                 \
    { static Return convention    Fn(Args... args) { return GetInvoker()->operator()(args...); } };  \
  static     Return convention  name(Args... args) { return GetInvoker()->operator()(args...); }
  static     Return          Default(Args... args) { return GetInvoker()->operator()(args...); }
  PATCHER_EMIT_CALLS(PATCHER_LAMBDA_INVOKER_CONVERSION_DEF);
};
///@}

#if __cpp_return_type_deduction  // Use C++14 auto return type to work around MSVC Intellisense bugs.
# define PATCHER_INVOKE_DEF(name)  constexpr auto*
#else
# define PATCHER_INVOKE_DEF(name)  constexpr decltype(&Impl::LambdaInvoker<T>::name)
#endif
} // Impl

namespace Util {
///@{ Converts a non-capturing lambda or stateless functor to a function pointer (of the specified calling convention).
///   The returned function pointer can be passed to PatchContext methods, as well as having general callable uses.
#define PATCHER_LAMBDA_PTR_DEF(convention, name, ...)  \
template <typename T>  PATCHER_INVOKE_DEF(name)  name##LambdaPtr(T) { return &Impl::LambdaInvoker<T>::name;    }
template <typename T>  PATCHER_INVOKE_DEF(Default)     LambdaPtr(T) { return &Impl::LambdaInvoker<T>::Default; }
template <Call C, typename T>
PATCHER_INVOKE_DEF(template As<C>::Fn)      LambdaPtr(T) { return &Impl::LambdaInvoker<T>::template As<C>::Fn; }
PATCHER_EMIT_CALLS(PATCHER_LAMBDA_PTR_DEF);
///@}
} // Util


namespace Impl {
/// @internal  Number of extra args needed to call FunctionRef::InvokeFunctor().
constexpr size_t InvokeFunctorNumArgs = 2;

/// @internal  Calculate # of alignment padders that must be passed to an InvokeFunctor() variant before the extra args.
constexpr size_t GetInvokeFunctorNumPadders(size_t stackAlignment = PATCHER_DEFAULT_STACK_ALIGNMENT)
  { return ((stackAlignment / RegisterSize) - 1) - ((InvokeFunctorNumArgs - 1) % (stackAlignment / RegisterSize)); }

///@{ @internal  Helper metafunction that produces a BoolSequence for whether args should be placed in registers or not.
///
/// @warning POD type detection, particularly large struct types, can produce false positives, especially without C++17.
///          This becomes yet more problematic with calling conventions that allow GPR splitting (Regcall and Regparm*).
///
///          For example, with C++17, neither "struct { char c; int i; }" nor "struct { float f; }" would be placed in
///          SGPRs, but C++11/14 cannot handle these cases correctly.
///
///          For another, "struct { int x; int y; }" would correctly be detected as being allowed to split GPRs; while
///          "struct { int x[2]; }" shouldn't, yet tests as a false positive, leading to an incorrect result.  If C++23
///          adds "Structured Bindings can introduce a Pack" (P1061), the latter case should be fixable.
template <Call C, size_t Remaining, typename Arg = void, typename... Args>
struct InvokeFunctorSgprMapper {
  static constexpr uint32 Flags           = GetCallTraits(C).flags;
  static constexpr bool   IsBasicType     = (std::is_scalar<Arg>::value || std::is_reference<Arg>::value);
  static constexpr bool   IsSplittablePod =
    IsUniquePod<Arg>() && Util::IsAligned(alignof(Arg), RegisterSize) && Util::IsAligned(sizeof(Arg), RegisterSize);

  static constexpr size_t NumNeeded = (std::is_empty<Arg>::value ? ~0 : (ArgSize<Arg, C>() / RegisterSize));
  static constexpr size_t Available = ((Flags & CallTraits::AnyTypeGprSplit) ||
    ((IsBasicType || IsSplittablePod) && (Flags & CallTraits::PodTypeGprSplit))) ? Remaining : 1;

  static constexpr bool PlaceInSgpr = (NumNeeded <= Available) && (IsVectorArg<Arg>() == false) && (IsBasicType ||
    (Flags & CallTraits::AnyTypesInGprs) || (IsUniquePod<Arg>() && (Flags & CallTraits::PodTypesInGprs)));

  using Type = ConcatSeq<BoolSequence<PlaceInSgpr>,
                         typename InvokeFunctorSgprMapper<C, Remaining - (PlaceInSgpr ? NumNeeded : 0), Args...>::Type>;
};

template <Call C, size_t Remaining> struct InvokeFunctorSgprMapper<C, Remaining, void> { using Type = BoolSequence<>; };

template <Call C, typename Arg, typename... Args>
struct InvokeFunctorSgprMapper<C, 0, Arg, Args...> { using Type = BoolSequence<false, (ToVoid<Args>(0), false)...>; };
///@}

/// @internal  Helper metafunction to reorder function args so that we can inject extra stack arguments.
template <Call C, typename R, typename... Args>
struct InvokeFunctorArgMapper {
  static constexpr size_t NumSgprs       = GetCallTraits(C).numArgSgprs;
  // ** TODO Does NumUserSgprs take into account this ptr correctly, especially when (NumSgprs == 1) && IsAggregateRetn?
  static constexpr size_t NumUserSgprs   = (NumSgprs == 0) ? 0 : (NumSgprs - (IsAggregateReturnArg<R, C>() ? 1 : 0));
  static constexpr bool   HasShadowSpace = GetCallTraits(C).flags & CallTraits::ShadowSpace;

  using Indexes           = MakeIndexSequence<sizeof...(Args)>;
  using SgprArgIndexes    = FilterSeq<Indexes, typename InvokeFunctorSgprMapper<C, NumUserSgprs, Args...>::Type>;
  using NonSgprArgIndexes = SpliceSeq<Indexes, SgprArgIndexes>;
  using ArgSwizzle        = ConcatSeq<SgprArgIndexes, NonSgprArgIndexes>;

  static constexpr size_t NumUnusedSgprs =
    (NumUserSgprs > SeqSize(SgprArgIndexes{})) ? (NumUserSgprs - SeqSize(SgprArgIndexes{})) : 0;

  using ArgOrder    = SeqSort<ArgSwizzle, KeySeqCompare<ArgSwizzle>>;
  using SgprArgs    = SeqElements<TypeSequence<Args...>, SgprArgIndexes>;
  using Padders     = MakeTypeSequence<int, NumUnusedSgprs + GetInvokeFunctorNumPadders(GetStackAlignment<Args...>())>;
  using ShadowSpace = MakeTypeSequence<int, HasShadowSpace ? NumSgprs : 0>;
  using OtherArgs   = SeqElements<TypeSequence<Args...>, NonSgprArgIndexes>;
};

/// @internal  Helper metafunction to get a plain wrapper function of any calling convention which invokes a functor via
///            "hidden" extra arguments.  These args are passed on the stack by functor thunk or LowLevelHook code.
// ** TODO Should maybe try to make this and LambdaInvokerImpl look more similar?
template <typename T, typename R, typename... Args>
class GetFunctorInvoker {
public:
  template <Call C = Call::Default>  static constexpr const void* Get() { return (void*)(&Fn<C>::Invoke); }

private:
  using ReturnPtr = AddPointer<R>;

  template <Call, typename ArgOrder, typename RegisterArgs, typename Padders, typename ShadowSpace, typename OtherArgs,
            size_t NumSgprArgs,  bool AggregateReturn>
  struct FnImpl;

  // Invokes a functor through a pointer to an object instance.
  //
  // Note that if there is a "this" pointer arg, AggregateReturn can never be true, as the return type is already R*.
# define PATCHER_FUNCTOR_INVOKER_CONVERSION_DEF(conv, name, ...)                                                     \
  template <size_t...   ArgOrder,  typename... SgprArgs, typename... Padders, typename... ShadowSpace,               \
            typename... OtherArgs, size_t NumSgprArgs,   bool AggregateReturn>                                       \
  struct FnImpl<Call::name, IndexSequence<ArgOrder...>, TypeSequence<SgprArgs...>, TypeSequence<Padders...>,         \
                TypeSequence<ShadowSpace...>, TypeSequence<OtherArgs...>, NumSgprArgs, AggregateReturn>              \
  {                                                                                                                  \
    static R conv Invoke(                                                                                            \
      SgprArgs... sgprArgs, Padders..., T* pFunctor, void* pPrevReturnAddr, ShadowSpace..., OtherArgs... otherArgs)  \
    {                                                                                                                \
      const auto args = std::forward_as_tuple(sgprArgs..., otherArgs...);                                            \
      return (*pFunctor)(std::get<ArgOrder>(args)...);                                                               \
    }                                                                                                                \
  };                                                                                                                 \
                                                                                                                     \
  template <typename ArgOrder, typename... Padders, typename... Args>                                                \
  struct FnImpl<                                                                                                     \
    Call::name, ArgOrder, TypeSequence<>, TypeSequence<Padders...>, TypeSequence<>, TypeSequence<Args...>, 0, true>  \
  {                                                                                                                  \
    static ReturnPtr conv Invoke(Padders..., T* pFunctor, void* pPrevReturnAddr, ReturnPtr pResult, Args... args)    \
      { *pResult = (*pFunctor)(args...);  return pResult; }                                                          \
  };
  PATCHER_EMIT_CALLS(PATCHER_FUNCTOR_INVOKER_CONVERSION_DEF);

  template <Call C, typename Mapper = InvokeFunctorArgMapper<C, R, Args...>>
  using Fn = FnImpl<C, typename Mapper::ArgOrder,    typename Mapper::SgprArgs,  typename Mapper::Padders,
                       typename Mapper::ShadowSpace, typename Mapper::OtherArgs,          Mapper::NumSgprs,
                       IsAggregateReturnArg<R, C>()>;
};


///@{ @internal  Helper metafunction for implementing register type and by reference deduction for LowLevelHook().
template <typename    T>  using  GetRegisterInfoTraits =
  Conditional<std::is_function<RemoveCvRefPtr<T>>::value, FuncTraits<T>, FuncTraitsNoThis<T>>;

template <typename    T>  struct GetRegisterInfo : public GetRegisterInfo<typename GetRegisterInfoTraits<T>::Params>{};

template <typename... A>  struct GetRegisterInfo<TypeSequence<A...>> {
  using Arr = Conditional<(sizeof...(A) == 0), std::nullptr_t, RegisterInfo[sizeof...(A) + (sizeof...(A) == 0)]>;
  static constexpr Arr Info = { { RemoveCvRefPtr<A>::RegisterId, IsRefPtr<A>(), RemoveCvRefPtr<A>::StackOffset }... };
};
///@}


/// Literal array type.  Useful for making arrays of arrays where the inner arrays have variable length (up to MaxSize).
template <typename T, size_t MaxSize>
class ConstArray {
public:
  constexpr ConstArray() : data_{ }, size_(0) { }
  template <typename... Ts>  constexpr ConstArray(Ts... e) : data_{ T(e)... }, size_(sizeof...(e)) { }
  constexpr operator const Array<T, MaxSize>&() const { return data_; }  ///< Array conversion, provides operator[].
  constexpr size_t Size()                       const { return size_; }  ///< Size in elements.

private:
  const T       data_[MaxSize];
  const size_t  size_;
};


///@{ @internal  Helpers for creating a dummy object instance.  Used as a target for GetVftable() in PmfCast().
template <typename T, bool = std::is_polymorphic<T>::value && (std::is_abstract<T>::value == false)>
struct DummyFactory { static T* Create(void* pPlacementAddr) { return nullptr; } static void Destroy(const void*) { } };

// Used by DummyFactory::MatchCtor to find user-defined constructors.
struct DummyArg {
  template <typename T>  using DummyType = Conditional<std::is_default_constructible<T>::value, T, TypeStorage<T>>;
  // Making this conversion operator const prevents ambiguous call errors with the other (preferred) conversion.
  template <typename T, typename = EnableIf<std::is_const<T>::value == false>>
                         operator T&() const { static DummyType<T> x{};  return reinterpret_cast<T&>(x); }
  template <typename T>  operator T()        {        DummyType<T> x{};  return reinterpret_cast<T&>(x); }
};

template <typename T>
struct DummyFactory<T, true> {
  template <typename U>
  static constexpr bool UseCopyMove() {
    return (std::is_default_constructible<U>::value == false) &&
           (std::is_copy_constructible<U>::value || std::is_move_constructible<U>::value);
  }

  // Template metafunction to attempt to find a user-defined constructor by filling in arguments with DummyArgs.
  template <typename = void, typename... A>
  struct MatchCtor {
    template <typename U = T*>  static auto Create(void* p) -> EnableIf<(sizeof...(A) >= 25), U> { return nullptr; }
    template <typename U = T>   static auto Create(void* p) -> EnableIf<(sizeof...(A) <  25), U*>
      { return MatchCtor<void, A..., DummyArg>::Create(p); }
  };
  template <typename... A>  struct MatchCtor<ToVoid<decltype(T(A{}...))>, A...>
    { static T* Create(void* p) { PATCHER_UNSAFE_TRY(new(p) T(A{}...));  return static_cast<T*>(p); } };

  // Try to use default constructor, or any user-defined constructor up to 25 params (unless it's an ambiguous call)
  // Warning:  If using non-default constructor, zeroed buffers as args may be unsafe depending on the implementation!
  template <typename U = T>  static auto Create(void* pPlacementAddr) -> EnableIf<UseCopyMove<U>() == false, T*>
    { return MatchCtor<>::Create(pPlacementAddr); }

  template <typename U = T>
  static constexpr auto MaybeMove(T& arg) -> EnableIf<std::is_move_constructible<U>::value == false, T&> { return arg; }
  template <typename T2>  static constexpr auto MaybeMove(T2&& arg)
    -> EnableIf<std::is_move_constructible<T>::value, RemoveRef<T2>&&> { return static_cast<RemoveRef<T2>&&>(arg); }

  // Warning:  This move/copy construction from a zeroed buffer may be unsafe depending on the implementation!
  template <typename U = T>
  static auto Create(void* pPlacementAddr) -> EnableIf<UseCopyMove<U>(), U*> {
    TypeStorage<T> emptyData = { };
    PATCHER_UNSAFE_TRY(new(pPlacementAddr) T(MaybeMove(reinterpret_cast<T&>(emptyData))));
    return static_cast<T*>(pPlacementAddr);
  }

  template <typename U = T>  static auto Destroy(T* p) -> EnableIf<IsDestroyable<U>()> { PATCHER_UNSAFE_TRY(p->~T()); }
  template <typename U = T>  static auto Destroy(const void*) -> EnableIf<IsDestroyable<U>() == false> { }
};
///@}
} // Impl

namespace Util {
// =====================================================================================================================
/// Cast any non-reference type to another type.  Similar to reinterpret_cast, but works with e.g. pointer-to-members.
template <typename T, typename U>
T UnsafeCast(U&& src) { const union { U in;  T out; } cast = { std::forward<U>(src) };  return cast.out; }

// =====================================================================================================================
/// Cast pointer-to-member-variable to offset in bytes.
template <typename T, typename U, typename = Impl::EnableIf<std::is_function<U>::value == false>>
size_t PmvCast(U T::* pmv, const T* pThis = nullptr) { return PtrDelta(&pThis->*pmv, pThis); }

// =====================================================================================================================
/// Helper function for getting the virtual function table for a given type.  If an object instance is not provided, a
/// dummy instance will attempt to be created - this may potentially be unsafe depending on constructor implementation!
template <typename T>
void** GetVftable(
  const T* pThis = nullptr)
{
  void** pVftable = nullptr;

  if (std::is_polymorphic<T>::value) {
    if ((pThis == nullptr) || (*reinterpret_cast<void*const*>(pThis) == nullptr)) {
      Impl::TypeStorage<T> dummy = { };
      T*const pLocalSelf = Impl::DummyFactory<T>::Create(&dummy);

      if (pLocalSelf != nullptr) {
        pVftable = *reinterpret_cast<void***>(pLocalSelf);
        Impl::DummyFactory<T>::Destroy(pLocalSelf);
      }
    }
    else if (pThis != nullptr) {
      pVftable = *reinterpret_cast<void**const*>(pThis);
    }
  }

  return pVftable;
}

// =====================================================================================================================
/// Cast pointer-to-member-function to a standard pointer-to-function.
/// @note  For virtual PMFs, either an object instance must be provided, or a dummy object instance will attempt to be
///        created (may be unsafe!).  Class cannot multiply inherit.
/// @see   PATCHER_MFN_PTR() macro, which is more robust for certain compilers and more reliable for virtual methods.
template <typename Fn, typename T>
auto PmfCast(
  Fn    T::*  pmf,
  const T*    pThis = nullptr
  ) -> typename Impl::FuncTraits<decltype(pmf)>::Pfn
{
  union {
    decltype(pmf)  pmfIn;
    void*          pOut;
    size_t         vftOffset;
  } cast = {pmf};

  // Test if this is a virtual PMF, which requires special compiler-specific handling and an object instance.  If so and
  // pThis was not provided, then we will need to try to create a dummy object instance in order to get the vftable. 
  // Non-virtual PMFs are straightforward to convert, and do not require an object instance.

#if PATCHER_UNIX_ABI
  // In the Itanium ABI (used by Unix), virtual PMFs have the low bit set to 1.
  if (std::is_polymorphic<T>::value && (cast.vftOffset & 1)) {
    // We need an object instance to get the vftable pointer, which is typically initialized during the constructor.
    void**const pVftable = GetVftable(pThis);
    cast.pOut = (pVftable != nullptr) ? pVftable[((cast.vftOffset - 1) / sizeof(void*))] : nullptr;
  }
#elif PATCHER_MS_ABI
  // MS ABI uses compiler-generated "vcall" thunks for calling through pointers-to-virtual-member-functions.
  // We have to parse the assembly of the thunk in order to get the offset into the vftable.
  // ** TODO Need to check what ICC does in MS mode
  static constexpr struct {
    Impl::ConstArray<uint8, 20>  bytes;
    uint8  operandBase;  // x86:  +0x0 for 0, +0x40 for byte operand, +0x80 for dword operand
  } Vcalls[] = {
# if   PATCHER_MSVC  && PATCHER_X86_64
    { { 0x48, 0x8B, 0x01, 0xFF },       0x20 },  // mov rax, [rcx];  jmp qword ptr [rax+?]
# elif PATCHER_MSVC  && PATCHER_X86_32
    { { 0x8B, 0x01, 0xFF },             0x20 },  // mov eax, [ecx];  jmp dword ptr [eax+?]
# elif PATCHER_CLANG && PATCHER_X86_64
    { { 0x48, 0x8B, 0x01, 0x48, 0x8B }, 0x00 },  // mov rax, [rcx];  mov rax, [rax+?]
    // sub rsp, 16;  mov [rsp+16+var_8], rcx;  mov rax, [rsp+16+var_8];  mov rcx, [rax];  mov rcx, [rcx+?]
    { { 0x48, 0x83, 0xEC, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x8B, 0x44, 0x24, 0x08, 0x48, 0x8B, 0x08, 0x48,
        0x8B }, 0x09 },
# elif PATCHER_CLANG && PATCHER_X86_32
    { { 0x8B, 0x01, 0x8B },             0x00 },  // mov eax, [ecx];  mov eax, [eax+?]
    // push esp; mov ebp, esp; sub esp, 8; mov [ebp+var_4], ecx; mov eax, [ebp+var_4]; mov ecx, [eax]; mov ecx, [ecx+?]
    { { 0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0xFC, 0x8B, 0x08, 0x8B }, 0x09 },
    // sub esp, 8;  mov [esp+8+var_4], ecx;  mov eax, [esp+8+var_4];  mov ecx, [eax];  mov ecx, [ecx+?]
    { { 0x83, 0xEC, 0x08, 0x89, 0x4C, 0x24, 0x04, 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x8B },       0x09 },
# else
    { }  // Unknown compiler or architecture; virtual PMF conversion unsupported.
# endif
  };

  if (std::is_polymorphic<T>::value && (Vcalls[0].bytes.Size() != 0)) {
# if PATCHER_INCREMENTAL_LINKING
    // Incremental linking (debug) gives us a pointer to a jump thunk to the vcall thunk.
    auto*const pReader = static_cast<uint8*>(cast.pOut);
    cast.pOut = (pReader[0] == 0xE9) ? (pReader + 5 + reinterpret_cast<int32&>(pReader[1])) : cast.pOut;
# endif

    for (const auto& vcall : Vcalls) {
      auto*const pOperand = PtrInc<uint8*>(cast.pOut, vcall.bytes.Size());
      if ((memcmp(cast.pOut, &vcall.bytes[0], vcall.bytes.Size()) == 0) &&
          ((*pOperand & vcall.operandBase) == vcall.operandBase))
      {
        // We need an object instance to get the vftable pointer, which is typically initialized during the constructor.
        void**const pVftable = GetVftable(pThis);

        const size_t offset =
          ((*pOperand) == (vcall.operandBase + 0x40)) ? pOperand[1]                            :  // Byte  operand size.
          ((*pOperand) == (vcall.operandBase + 0x80)) ? reinterpret_cast<uint32&>(pOperand[1]) :  // Dword operand size.
          0;

        cast.pOut = (pVftable != nullptr) ? pVftable[(offset / sizeof(void*))] : nullptr;
        break;
      }
    }
  }
#else
  static_assert(std::is_void<T>::value, "PmfCast is only supported in MSVC, GCC, ICC, or Clang.");
#endif

  return reinterpret_cast<typename Impl::FuncTraits<decltype(pmf)>::Pfn>(cast.pOut);
}

///@{ PATCHER_MFN_PTR helper macro to get the address of a class member function without requiring an object instance.
///
/// Notice that this takes a function identifier literal, not a pointer-to-member-function!
/// A pointer to an object instance may optionally be passed as a second arg, e.g. PATCHER_MFN_PTR(ClassA::Func, &obj),
/// but it may be ignored altogether on certain platforms/compilers.
///
/// @example  patcher.Hook(PATCHER_MFN_PTR(ClassA::Func), PATCHER_MFN_PTR(HookClassA::Func))
/// 
/// @note  This does not work on overloaded functions.  There may be compiler-specific limitations.
#if PATCHER_MSVC && PATCHER_X86_32
// MSVC (x86_32):  Inline __asm can reference C++ symbols, including virtual methods, by address.
# if PATCHER_INCREMENTAL_LINKING == false
#  define PATCHER_MFN_PTR(method, ...)  [] { using Pfn = typename Patcher::Impl::FuncTraits<decltype(&method)>::Pfn;  \
     struct { static Pfn Get() { __asm mov eax, method } } p;  return p.Get(); }()

# else
// Incremental linking (debug) conflicts with this method somewhat and gives you a pointer to a jump thunk instead.
#  define PATCHER_MFN_PTR(method, ...)  [] {                                                               \
     struct { static Patcher::uint8* Get() { __asm mov eax, method } } p;                                  \
     auto*const pfn     = p.Get();                                                                         \
     void*const realPfn = (pfn[0] == 0xE9) ? (pfn + 5 + reinterpret_cast<Patcher::int32&>(pfn[1])) : pfn;  \
     return reinterpret_cast<typename Patcher::Impl::FuncTraits<decltype(&method)>::Pfn>(realPfn);         \
   }()
# endif

#elif PATCHER_GXX && (PATCHER_CLANG == false)
// GCC-compliant:  GCC has an extension to cast PMF constants to pointers without an object instance, which is ideal.
# define PATCHER_MFN_PTR(method, ...)  [] { PATCHER_IGNORE_GCC_WARNING("-Wpmf-conversions",  \
   return reinterpret_cast<typename Patcher::Impl::FuncTraits<decltype(&method)>::Pfn>(&method);) }()

#else
// MSVC (non-x86_32), Clang, other:  See comments of PmfCast about restrictions.
# define PATCHER_MFN_PTR(method, ...)  Patcher::Util::PmfCast(&method, {__VA_ARGS__})
#endif
///@}
} // Util

} // Patcher
