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

namespace Patcher {

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
# if   defined(_MSC_VER) || defined(__ICL)
#  define PATCHER_MS_ABI    1
# elif PATCHER_GXX
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
# if PATCHER_MS_ABI
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
#elif PATCHER_GXX
# define  PATCHER_CDECL       PATCHER_ATTRIBUTE(__cdecl__)
# define  PATCHER_STDCALL     PATCHER_ATTRIBUTE(__stdcall__)
# define  PATCHER_FASTCALL    PATCHER_ATTRIBUTE(__fastcall__)
# define  PATCHER_THISCALL    PATCHER_ATTRIBUTE(__thiscall__)
# define  PATCHER_VECTORCALL  PATCHER_ATTRIBUTE(__vectorcall__)
# define  PATCHER_REGCALL     PATCHER_ATTRIBUTE(__regcall__)
# define  PATCHER_REGPARM(n)  PATCHER_ATTR_PARM(__regparm__, n)
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

/// @internal  Macro that takes a macro which takes (convention, name, passthru...) as args, and invokes it for each
///            calling convention.
#if PATCHER_X86_32
# define PATCHER_EMIT_CALLS($, ...)  PATCHER_IGNORE_GCC_WARNING("-Wignored-attributes",               \
  $(PATCHER_CDECL,       Cdecl,       __VA_ARGS__)  $(PATCHER_STDCALL,     Stdcall,     __VA_ARGS__)  \
  $(PATCHER_FASTCALL,    Fastcall,    __VA_ARGS__)  $(PATCHER_THISCALL,    Thiscall,    __VA_ARGS__)  \
  $(PATCHER_VECTORCALL,  Vectorcall,  __VA_ARGS__)  $(PATCHER_REGCALL,     Regcall,     __VA_ARGS__)  \
  $(PATCHER_REGPARM(1),  Regparm1,    __VA_ARGS__)  $(PATCHER_REGPARM(2),  Regparm2,    __VA_ARGS__)  \
  $(PATCHER_REGPARM(3),  Regparm,     __VA_ARGS__)  $(PATCHER_SSEREGPARM,  SseRegparm,  __VA_ARGS__))
#elif PATCHER_X86_64 && PATCHER_GXX && (PATCHER_CLANG == false)
# define PATCHER_EMIT_CALLS($, ...)  PATCHER_IGNORE_GCC_WARNING("-Wignored-attributes",               \
  $(PATCHER_MSCALL,      Mscall,      __VA_ARGS__)  $(PATCHER_UNIXCALL,    Unixcall,    __VA_ARGS__))
#elif PATCHER_X86_64
# define PATCHER_EMIT_CALLS($, ...)  PATCHER_IGNORE_GCC_WARNING("-Wignored-attributes",               \
  $(PATCHER_MSCALL,      Mscall,      __VA_ARGS__)  $(PATCHER_VECTORCALL,  Vectorcall,  __VA_ARGS__)  \
  $(PATCHER_UNIXCALL,    Unixcall),   __VA_ARGS__))
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
#define PATCHER_EMIT_PMF_THIS_QUALIFIERS($)  $(,)  $(,&)  $(,&&)  $(const,)  $(const, &)  $(const, &&)  \
  $(volatile,)  $(volatile, &)  $(volatile, &&)  $(const volatile,)  $(const volatile, &)  $(const volatile, &&)

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

// Typedefs

using int8    = int8_t;
using int16   = int16_t;
using int32   = int32_t;
using int64   = int64_t;
using uint8   = uint8_t;
using uint16  = uint16_t;
using uint32  = uint32_t;
using uint64  = uint64_t;
using uintptr = uintptr_t;

namespace Impl {
struct Dummy { explicit constexpr Dummy() { } };         ///< @internal  Empty dummy parameter type.  
template <typename...>  struct DummyT : public Dummy{};  ///< @internal  Empty template-able dummy parameter type.
}

namespace Registers { enum class Register : uint8; }

/// Info about registers requested by LowLevelHook().
struct RegisterInfo {
  Registers::Register type;         ///< Register type.
  bool                byReference;  ///< Pass register by reference for writing? (Not needed with stack values)
  uint32              offset;       ///< (Stack only) Offset into the stack associated with this value.
};

/// Enum specifying a function's calling convention.
enum class Call : uint32 {
#define PATCHER_CALLING_CONVENTION_ENUM_DEF(conv, name, ...) name,
#define PATCHER_DEFAULT_CALLING_CONVENTION_ENUM_DEF(c, name, ...) std::is_same<void(*)(), void(c*)()>::value ? name :
#define PATCHER_MEMBER_CALLING_CONVENTION_ENUM_DEF(conv, name, ...)  \
  std::is_same<void(Impl::Dummy::*)(), void(conv Impl::Dummy::*)()>::value ? name :

  Unknown = 0,
  PATCHER_EMIT_CALLS(PATCHER_CALLING_CONVENTION_ENUM_DEF)
  Count,

  Default  = PATCHER_EMIT_CALLS(PATCHER_DEFAULT_CALLING_CONVENTION_ENUM_DEF) Unknown,
  Member   = PATCHER_EMIT_CALLS(PATCHER_MEMBER_CALLING_CONVENTION_ENUM_DEF)  Unknown,
#if PATCHER_X86_32
  AbiStd   = Cdecl,
#elif PATCHER_X86_64
  AbiStd   = IsMsAbi ? Mscall : IsUnixAbi ? Unixcall : Unknown,
#endif
  Variadic = AbiStd,
};

namespace Util {
///@{ Templated dummy parameter type that can be used to pass a calling convention as a templated function argument.
template <Call C>  struct AsCall{};
#define PATCHER_ASCALL_DEF(conv, name, ...)  constexpr auto As##name = AsCall<Call::name>{};
PATCHER_EMIT_CALLS(PATCHER_ASCALL_DEF);
///@}


///@{ Pointer arithmetic helpers.
template <typename T = void*>       T PtrInc(void*       p, size_t offset) { return T((uint8*)(p)       + offset); }
template <typename T = const void*> T PtrInc(const void* p, size_t offset) { return T((const uint8*)(p) + offset); }

template <typename T = void*>       T PtrDec(void*       p, size_t offset) { return T((uint8*)(p)       - offset); }
template <typename T = const void*> T PtrDec(const void* p, size_t offset) { return T((const uint8*)(p) - offset); }

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
} // Util


namespace Impl {
///@{ @internal  Returns the sum of the values.  Intended usage is with an expanded non-type parameter pack.
template <typename T = size_t>         constexpr T Sum()                { return 0;                   }
template <typename T, typename... Ts>  constexpr T Sum(T a, Ts... next) { return a + Sum<T>(next...); }
///@}

///@{ @internal  Type traits convenience aliases.
template <typename T>                using RemovePtr      = typename std::remove_pointer<T>::type;
template <typename T>                using RemoveRef      = typename std::remove_reference<T>::type;
template <typename T>                using RemoveConst    = typename std::remove_const<T>::type;
template <typename T>                using RemoveCv       = typename std::remove_cv<T>::type;
template <typename T>                using RemoveCvRef    = RemoveCv<RemoveRef<T>>;
template <typename T>                using RemoveCvRefPtr = RemoveCvRef<RemovePtr<T>>;
template <typename T>                using RemoveExtents  = typename std::remove_all_extents<T>::type;
template <typename T>                using Decay          = typename std::decay<T>::type;
template <typename T>                using AddLvalueRef   = typename std::add_lvalue_reference<T>::type;
template <bool B, class T = void>    using EnableIf       = typename std::enable_if<B, T>::type;
template <typename... T>             using ToVoid         = void;
template <bool B, class T, class F>  using Conditional    = typename std::conditional<B, T, F>::type;
template <typename T>                using TypeStorage    = typename std::aligned_storage<sizeof(T), alignof(T)>::type;
template <typename... Ts>            using CommonType     = typename std::common_type<Ts...>::type;
template <typename T, size_t N>      using Array          = T[N];
template <typename T>                using AddPtrIfValue  =
  Conditional<(std::is_reference<T>::value || std::is_pointer<T>::value), T, typename std::add_pointer<T>::type>;

template <typename T, bool = std::is_enum<T>::value>  struct UnderlyingTypeImpl { using Type = T; };
template <typename T>  struct UnderlyingTypeImpl<T, true> { using Type = typename std::underlying_type<T>::type; };

template <typename T>  using UnderlyingType = typename UnderlyingTypeImpl<T>::Type;
///@}


template <typename T, T... Elements>  struct ValueSequence{};                            ///< Parameter pack of values.
template <size_t... Indices>  using IndexSequence = ValueSequence<size_t, Indices...>;   ///< Parameter pack of size_t.
template <typename... Ts>     struct TypeSequence { using Tuple = std::tuple<Ts...>; };  ///< Parameter pack of types.


template <size_t N, typename T, typename = void>  struct TupleElementImpl { typedef struct NotFound{} Type; };
template <size_t N, typename T>  struct TupleElementImpl<N, T, EnableIf<(N < std::tuple_size<T>::value)>>
  { using Type = typename std::tuple_element<N, T>::type; };
template <size_t N, typename... Ts>
struct TupleElementImpl<N, TypeSequence<Ts...>, void> : public TupleElementImpl<N, std::tuple<Ts...>, void>{};

template <size_t N, typename T>  using TupleElement = typename TupleElementImpl<N, T>::Type;


///@{ @internal  Helper metafunctions to generate parameter packs of sequences.
template <typename SeqA, typename SeqB>      struct ConcatSeqImpl;
template <typename T, T... SeqA, T... SeqB>  struct ConcatSeqImpl<ValueSequence<T, SeqA...>, ValueSequence<T, SeqB...>>
  { using Type = ValueSequence<T, SeqA..., SeqB...>; };

template <typename T, T Begin, size_t Length>  struct MakeSeqRangeImpl;
template <typename T, T Begin, size_t Length>  using MakeSeqRange = typename MakeSeqRangeImpl<T, Begin, Length>::Type;

template <typename T, T Begin>        struct MakeSeqRangeImpl<T, Begin, 0> { using Type = ValueSequence<T>;        };
template <typename T, T Begin>        struct MakeSeqRangeImpl<T, Begin, 1> { using Type = ValueSequence<T, Begin>; };
template <typename T, T B, size_t L>  struct MakeSeqRangeImpl
  { using Type = typename ConcatSeqImpl<MakeSeqRange<T, B, (L/2)>, MakeSeqRange<T, B + (L/2), L - (L/2)>>::Type; };

template <typename Seq, typename T>  struct MakeTypeSeqImpl;
template <size_t, typename T>        using  IndexToType = T;
template <typename T, size_t... Is>
struct MakeTypeSeqImpl<IndexSequence<Is...>, T> { using Type = TypeSequence<IndexToType<Is, int>...>; };
///@}

/// @internal  Makes an IndexSequence from [0..Length).
template <size_t Length>              using MakeIndexSequence = MakeSeqRange<size_t, 0, Length>;
/// @internal  Makes an IndexSequence from [Begin..End).
template <size_t Begin, size_t End>   using MakeIndexRange    = MakeSeqRange<size_t, Begin, (End - Begin)>;
/// @internal  Makes a homogenous TypeSequence of Length elements.
template <typename T, size_t Length>
using MakeTypeSequence = typename MakeTypeSeqImpl<MakeIndexSequence<Length>, T>::Type;


/// @internal  Returns the larger of a or b.
template <typename T1, typename T2, typename U = CommonType<T1, T2>>
constexpr U Max(const T1& a, const T2& b) { return (static_cast<U>(a) > static_cast<U>(b)) ? a : b; }

/// @internal  Returns the smaller of a or b.
template <typename T1, typename T2, typename U = CommonType<T1, T2>>
constexpr U Min(const T1& a, const T2& b) { return (static_cast<U>(a) < static_cast<U>(b)) ? a : b; }

/// @internal  Gets the length of an array.
template <typename T, size_t N>  constexpr uint32 ArrayLen(const T (&src)[N]) { return static_cast<uint32>(N); }


///@{ @internal  Template metafunction used to obtain function call signature information from a callable.
template <typename T, typename = void>  struct FuncTraitsImpl   :   public FuncTraitsImpl<decltype(&T::operator())>{};
template <typename T>                   using  FuncTraits       = typename FuncTraitsImpl<Decay<T>>::Type;
template <typename T>                   using  FuncTraitsNoThis = typename FuncTraits<T>::StripThis;
///@}

///@{ @internal  Template aliases that expand to void if the specified calling convention exists, else to a dummy type.
template             <typename Pfn, Call C>  using EnableIfConventionExists    = Conditional<
  (Call::Default == C) || (std::is_same<void(*)(),    Pfn>::value == false),  void,  Util::AsCall<C>>;
template <typename T, typename Pmf, Call C>  using EnableIfConventionExistsPmf = Conditional<
  (Call::Member  == C) || (std::is_same<void(T::*)(), Pmf>::value == false),  void,  Util::AsCall<C>>;
///@}

///@{ @internal  Implementation for helper template which breaks out qualifiers from a PMF.
template <typename T, typename = void>  struct TokenizePmfQualifiers;
#define PATCHER_TOKENIZE_PMF_QUALIFIERS_DEF(conv, name, cv, ref, ...)                                                  \
template <typename T, typename R, typename... A>                                                                       \
struct TokenizePmfQualifiers<R(conv T::*)(A...) cv ref, EnableIfConventionExistsPmf<T, void(conv T::*)(), Call::name>> \
  { using Pmf = R(T::*)(A...);  using This = AddPtrIfValue<cv T ref>;  static constexpr auto Convention = Call::name; };
PATCHER_EMIT_PMF_QUALIFIERS(PATCHER_TOKENIZE_PMF_QUALIFIERS_DEF);
///@}

/// @internal  Helper template alias that strips qualifiers from a PMF.  Useful for simplifying template matching.
template <typename T>  using StripPmfQualifiers = typename TokenizePmfQualifiers<T>::Pmf;

/// @internal  Returns sizeof(T), except void and empty types always return 0.
template <typename T, bool Empty = (std::is_void<T>::value || std::is_empty<T>::value)>
constexpr size_t SizeOfType() { return Empty ? 0 : sizeof(Conditional<Empty, int, T>); }

/// @internal  Gets a type's aligned size when passed as a function argument.
template <typename T>  constexpr size_t ArgSize()
#if   PATCHER_X86_32
  { return Util::Align(SizeOfType<Decay<Conditional<std::is_reference<T>::value, Decay<T>*, T>>>(), RegisterSize); }
#elif PATCHER_X86_64
  { return (SizeOfType<T>() == 0) ? 0 : RegisterSize; }
#else
  { return 0; }
#endif

/// @internal  Returns true if T is a floating-point or intrinsic vector type.
// ** TODO add vector type detection
template <typename T>  constexpr bool IsVectorArg() { return std::is_floating_point<T>::value; }

///@{ @internal  AddConvention helper to convert function types to function pointers of other calling conventions.
template <typename T, Call C>  struct AddConvImpl{};
template <typename T, Call C>  using  AddConvention = typename AddConvImpl<Decay<T>, C>::Type;

#define PATCHER_ADD_CONVENTION_DEF(conv, name, ...)  \
template <typename R, typename... A>  struct AddConvImpl<R(*)(A...), Call::name>    { using Type = R(conv*)(A...); };
template <typename R, typename... A>  struct AddConvImpl<R(*)(A...), Call::Unknown> { using Type = R(*)(A...);     };
template <typename R, typename... A, Call C>
struct AddConvImpl<R(*)(A..., ...), C> { using Type = R(*)(A..., ...); };
PATCHER_EMIT_CALLS(PATCHER_ADD_CONVENTION_DEF);
///@}

///@{ @internal  Template that defines typed function call signature information for use at compile time.
template <typename R, Call Call = Call::Default, bool Variadic = false, typename T = void, typename... A>
struct FuncSig {
  static constexpr size_t NumParams = std::is_void<T>::value ? 0 : (sizeof...(A) + 1);  ///< Number of function params.
  using Function = Conditional<NumParams==0, R(A...), R(T, A...)>;                      ///< Signature w/o convention.
  using Pfn      = AddConvention<Function, Call>;                                       ///< Function pointer signature.
  using Return   = R;                                                                   ///< Function return type.
  using Params   = Conditional<NumParams==0, TypeSequence<A...>, TypeSequence<T,A...>>; ///< Params as a TypeSequence.
  template <size_t N>  using Param = TupleElement<N, Params>;                           ///< Nth parameter's type.
  static constexpr size_t ParamSizes[]    = { ArgSize<T>(),     ArgSize<A>()...     };  ///< Aligned sizes of params.
  static constexpr bool   ParamIsVector[] = { IsVectorArg<T>(), IsVectorArg<A>()... };  ///< Are params float/vector?
  static constexpr bool   IsVariadic      = Variadic;                                   ///< Is function variadic?
  static constexpr auto   Convention      = Call;                                       ///< Calling convention.

  using StripThis = Conditional<  ///< Returns a FuncSig with the "this" (first) parameter removed.
    Call != Call::Unknown, FuncSig<R, Call::Unknown, Variadic, A...>, FuncSig<R, Call, Variadic, T, A...>>;
};

template <typename R, Call Call, typename T, typename... A>
struct FuncSig<R, Call, true, T, A...> : public FuncSig<R, Call, false, T, A...> {
  using First_   = Conditional<std::is_void<T>::value, int, T>;                        ///< Placeholder for first param.
  using Function = Conditional<std::is_void<T>::value, R(...), R(First_, A..., ...)>;  ///< Signature w/o convention.
  using Pfn      = AddConvention<Function, Call>;                                      ///< Function pointer signature.
  static constexpr bool IsVariadic = true;                                             ///< Is function variadic?
};
///@}

/// @internal  Defines untyped function call signature information for use at runtime.
struct RtFuncSig {
  /// Conversion constructor for the compile-time counterpart to this type, FuncSig.
  template <typename R, Call C, bool V, typename... A>
  constexpr RtFuncSig(FuncSig<R, C, V, A...>)
    : returnSize(SizeOfType<R>()),
      numParams(FuncSig<R, C, V, A...>::NumParams),
      pParamSizes(&FuncSig<R, C, V, A...>::ParamSizes[0]),
      pParamIsVector(&FuncSig<R, C, V, A...>::ParamIsVector[0]),
      totalParamSize(Sum(ArgSize<A>()...)),
      isVariadic(V),
      convention(C) { }

  /// Default constructor with unspecified call signature information.
  constexpr RtFuncSig()
    : returnSize(), numParams(), pParamSizes(), pParamIsVector(), totalParamSize(), isVariadic(), convention() { }

  size_t         returnSize;      ///< Size in bytes of the function's returned value.
  size_t         numParams;       ///< Number of parameters to call the function (including "this").
  const size_t*  pParamSizes;     ///< Aligned size in bytes of each parameter.
  const bool*    pParamIsVector;  ///< Specifies whether each parameter is floating-point/intrinsic vector type.
  size_t         totalParamSize;  ///< Total size in bytes of all @ref numParams parameters and alignment padding.
  bool           isVariadic;      ///< Specifies whether this is a variadic function.
  Call           convention;      ///< Function calling convention.
};

///@{ @internal  FuncTraitsImpl template metafunction used to obtain function call signature information from a callable
#define PATCHER_FUNC_TRAITS_DEF(conv, name, ...)                                                                 \
template <typename R, typename... A>                                                                             \
struct FuncTraitsImpl<R(conv*)(A...), EnableIfConventionExists<void(conv*)(), Call::name>>                       \
  { using Type = FuncSig<R, Call::name, false, A...>; };

#define PATCHER_FUNC_TRAITS_PMF_DEF(conv, name, cv, ref)                                                         \
template <typename R, typename T, typename... A>                                                                 \
struct FuncTraitsImpl<R(conv T::*)(A...) cv ref, EnableIfConventionExistsPmf<T, void(conv T::*)(), Call::name>>  \
  { using Type = FuncSig<R, Call::name, false, AddPtrIfValue<cv T ref>, A...>; };

#define PATCHER_FUNC_TRAITS_VARIADIC_PMF_DEF(cv, ref)                                                            \
template <typename R, typename T, typename... A>                                                                 \
struct FuncTraitsImpl<R(T::*)(A..., ...) cv ref, void>                                                           \
  { using Type = FuncSig<R, Call::Variadic, true, AddPtrIfValue<cv T ref>, A...>; };

template <typename R, typename... A>
struct FuncTraitsImpl<R(*)(A..., ...)> { using Type = FuncSig<R, Call::Variadic, true, A...>; };

PATCHER_EMIT_CALLS(PATCHER_FUNC_TRAITS_DEF);
PATCHER_EMIT_PMF_QUALIFIERS(PATCHER_FUNC_TRAITS_PMF_DEF);
PATCHER_EMIT_PMF_THIS_QUALIFIERS(PATCHER_FUNC_TRAITS_VARIADIC_PMF_DEF);
///@}


///@{ @internal  Helper template used in converting non-capturing lambdas (and stateless functors) to function pointers.
template <typename T, bool Empty>  struct LambdaInvokerImpl{};
template <typename T>
using LambdaInvoker = LambdaInvokerImpl<StripPmfQualifiers<decltype(&T::operator())>, std::is_empty<T>::value>;

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


/// Cast pointer-to-member-variable to offset in bytes.
template <typename T, typename U, typename = Impl::EnableIf<std::is_function<U>::value == false>>
size_t PmvCast(U T::* pmv, const T* pThis = nullptr) { return PtrDelta(&pThis->*pmv, pThis); }
} // Util


namespace Impl {
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


/// @internal  How many args that are passed via registers which must be skipped, determined by ABI.
constexpr size_t InvokeFunctorNumSkipped = (IsX86_64 && IsMsAbi) ? 4 : (IsX86_64 && IsUnixAbi) ? 6 : 0;
/// @internal  Max number of alignment padders that can be passed to an InvokeFunctor() variant.
constexpr size_t InvokeFunctorMaxPad     = Max((PATCHER_DEFAULT_STACK_ALIGNMENT / RegisterSize), 1) - 1;

/// @internal  Function table for invoking functors with varying # of alignment padders and stack cleanup modes.
struct InvokeFunctorTable {
  const void* pfnInvokeWithPad[InvokeFunctorMaxPad+1];           ///< Takes [i] padders at top of stack; caller-cleanup.
#if PATCHER_X86_32
  const void* pfnInvokeWithPadAndCleanup[InvokeFunctorMaxPad+1]; ///< Takes [i] padders at top of stack; callee-cleanup.
#endif
};

/// @internal  Helper template for getting the InvokeFunctorTable for a given functor type.  Used by FunctionRef.
template <typename T, typename Return, typename... Args>
struct GetInvokeFunctorTable {
  template <typename    T>  struct Fn;
  template <typename... Padders>
  struct Fn<TypeSequence<Padders...>> {
    static Return PATCHER_CDECL   Invoke(Padders..., T* pFunctor, void* pPrevReturnAddr, Args... args)
      { return (*pFunctor)(args...); }
#if PATCHER_X86_32
    static Return PATCHER_STDCALL InvokeWithCleanup(Padders..., T* pFunctor, void* pPrevReturnAddr, Args... args)
      { return (*pFunctor)(args...); }
#endif
  };

  static constexpr InvokeFunctorTable Get()
    { return Get(MakeIndexRange<InvokeFunctorNumSkipped, InvokeFunctorMaxPad + InvokeFunctorNumSkipped + 1>{}); }

  // Expands to the InvokeFunctorTable with all possible padding amount variants.
  // E.g. 0-3 padders expands to &Invoke(...), &Invoke(int, ...), &Invoke(int, int, ...), &Invoke(int, int, int, ...)
  template <size_t... Is>
  static constexpr InvokeFunctorTable Get(IndexSequence<Is...>) {
    return { { ((void*)(&Fn<MakeTypeSequence<int, Is>>::Invoke))...            }
#if PATCHER_X86_32
            ,{ ((void*)(&Fn<MakeTypeSequence<int, Is>>::InvokeWithCleanup))... } 
#endif
           };
  }
};


///@{ @internal  Helper metafunction for implementing register type and by reference deduction for LowLevelHook().
template <typename    T>  using  GetRegisterInfoTraits =
  Conditional<std::is_function<RemoveCvRefPtr<T>>::value, FuncTraits<T>, FuncTraitsNoThis<T>>;
template <typename    T>  struct GetRegisterInfo : public GetRegisterInfo<typename GetRegisterInfoTraits<T>::Params>{};
template <typename... A>  struct GetRegisterInfo<TypeSequence<A...>> {
  template <typename T>
  static constexpr bool IsRefPtr() { return (std::is_pointer<T>::value || std::is_reference<T>::value); }
  using Arr = Conditional<(sizeof...(A) == 0), std::nullptr_t, RegisterInfo[sizeof...(A) + (sizeof...(A) == 0)]>;
  static constexpr Arr Info = { { RemoveCvRefPtr<A>::RegisterId, IsRefPtr<A>(), RemoveCvRefPtr<A>::StackOffset }... };
};
///@}


///@{ @internal  Helpers for creating a dummy object instance.  Used as a target for GetVftable() in PmfCast().
template <typename T, bool = std::is_polymorphic<T>::value>
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
  template <typename U>  static constexpr bool Destroyable() { return std::is_destructible<U>::value; }
  template <typename U>  static constexpr bool UseCopyMove() {
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

  template <typename U = T>  static auto Destroy(T* p) -> EnableIf<Destroyable<U>()> { PATCHER_UNSAFE_TRY(p->~T()); }
  template <typename U = T>  static auto Destroy(const void*) -> EnableIf<Destroyable<U>() == false> { }
};
///@}
} // Impl

namespace Util {
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
  // In the Itanium ABI (used by GCC, Clang, etc. for x86), virtual PMFs have the low bit set to 1.
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
          ((*pOperand & vcall.operandBase) || (vcall.operandBase == 0)))
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

/// Helper macro to get the raw address of a class member function without requiring an object instance.
/// Usage: Hook(PATCHER_MFN_PTR(ClassA::Func), PATCHER_MFN_PTR(HookClassA::Func))
/// Notice that this takes a function identifier literal, not a pointer-to-member-function!
/// A pointer to an object instance may optionally be passed as a second arg, e.g. PATCHER_MFN_PTR(ClassA::Func, &obj).
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
} // Util

} // Patcher
