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

#include <initializer_list>
#include <functional>
#include <memory>

#include <cassert>

#include "PatcherMeta.h"

namespace Patcher {

class Allocator;  ///< @internal Code allocator class.

namespace Impl {

/// Type erasure reference accessor class for immutable, possibly temporary, array-like types.
template <typename T>
class Span {
public:
  constexpr Span(std::nullptr_t = nullptr)               : Span(nullptr,             0)                   { }
  constexpr Span(const T* pSrc, size_t length)           : pData_(pSrc),             length_(length)      { }
  constexpr Span(std::initializer_list<T> list)          : Span(list.begin(),        list.size())         { }
  template <size_t N>  constexpr Span(const T (&arr)[N]) : Span(&arr[0],             N)                   { }
  template <size_t N>
  constexpr Span(const ConstArray<T, N>& arr)            : Span(&arr[0],             arr.Size())          { }
  template <typename U, typename = EnableIf<std::is_same<decltype(std::declval<const U>().data()), const T*>::value>>
  constexpr Span(const U& stlContainer)                  : Span(stlContainer.data(), stlContainer.size()) { }

  constexpr const T* begin()  const noexcept { return pData_;           }
  constexpr const T* cbegin() const noexcept { return pData_;           }
  constexpr const T* end()    const noexcept { return pData_ + length_; }
  constexpr const T* cend()   const noexcept { return pData_ + length_; }

  constexpr const T* Data()     const noexcept { return pData_; }
  constexpr operator const T*() const noexcept { return pData_; }

  template <typename I>
  constexpr const T& operator[](I index) const noexcept { return *(pData_ + UnderlyingType<I>(index)); }

  constexpr size_t Length()  const { return length_;        }
  constexpr bool   IsEmpty() const { return (length_ == 0); }

private:
  const T*  pData_;
  size_t    length_;
};

/// RAII growable array container with a fixed-size initial storage buffer.
template <typename T, size_t InitialSize = 10>
class SmallVector {
public:
  SmallVector() : pData_(reinterpret_cast<T*>(&localStorage_[0])), numElements_(0), capacity_(InitialSize) { }
  explicit  SmallVector(size_t size) : numElements_(0), capacity_(Max(InitialSize, size))
    { pData_ = (size > ArrayLen(localStorage_)) ? static_cast<T*>(malloc(sizeof(T) * size)) : (T*)(&localStorage_[0]); }
  explicit  SmallVector(Span<T> src);
  template <size_t N>  SmallVector(const SmallVector<T, N>& src) : SmallVector(Span<T>(src.data(), src.size())) { }
  template <size_t N>  SmallVector(SmallVector<T, N>&& src);

  ~SmallVector()
    { Clear();  free((static_cast<void*>(pData_) != &localStorage_[0]) ? pData_ : nullptr); }

                  T* begin()        noexcept { return pData_;                }
  constexpr const T* begin()  const noexcept { return pData_;                }
  constexpr const T* cbegin() const noexcept { return pData_;                }
                  T* end()          noexcept { return pData_ + numElements_; }
  constexpr const T* end()    const noexcept { return pData_ + numElements_; }
  constexpr const T* cend()   const noexcept { return pData_ + numElements_; }

  constexpr size_t size()  const noexcept { return numElements_;  }
  constexpr bool   empty() const noexcept { return (size() == 0); }

                  T* data()       noexcept { return pData_; }
  constexpr const T* data() const noexcept { return pData_; }

  template <typename I>
                  T& operator[](I index) noexcept       { return *(pData_ + UnderlyingType<I>(index)); }
  template <typename I>
  constexpr const T& operator[](I index) const noexcept { return *(pData_ + UnderlyingType<I>(index)); }

  bool Reserve(size_t newCapacity);
  bool Grow(size_t numElements) {
    const size_t totalElements = numElements_ + numElements;
    return Reserve((totalElements > capacity_) ? Max((totalElements + capacity_), (capacity_ * 2)) : 0);
  }

  void Clear() {
    if ((IsPod == false) && (pData_ != nullptr)) {
      for (size_t i = 0; i < numElements_; pData_[i++].~T());
    }
    numElements_ = 0;
  }

  bool Push(const T& element) { return Grow(1) && (new(pData_ + (numElements_++)) T(element));            }
  bool Push(T&&      element) { return Grow(1) && (new(pData_ + (numElements_++)) T(std::move(element))); }

  template <typename... Ts>
  bool Emplace(Ts&&... args) { return Grow(1) && (new(pData_ + (numElements_++)) T(std::forward<Ts>(args)...)); }

  bool Append(Span<T> elements);

protected:
  static constexpr bool IsPod = std::is_trivially_copyable<T>::value;

  TypeStorage<T>  localStorage_[InitialSize];
  T*              pData_;
  size_t          numElements_;
  size_t          capacity_;
};


/// Type erasure wrapper for field offset arguments passed to PatchContext.
/// Can implicitly convert size_t, offsetof(), SetCapturedTrampoline, and pointers-to-member-variables.
class Offset {
public:
  /// Conversion constructor for pointers-to-members.  An object instance is required only in virtual inheritance cases.
  template <typename T, typename U>  Offset(U T::* pm, const T* pThis = nullptr) : offset_(Util::PmvCast(pm, pThis)) { }
  constexpr Offset(size_t offset) : offset_(offset) { }  ///< Conversion constructor for size_t.
  constexpr operator size_t() { return offset_; }        ///< Implicit conversion to size_t.
private:
  size_t offset_;  ///< Offset in bytes.
};


/// Type erasure wrapper for (possibly relocated) uint or pointer address arguments passed to PatchContext.
/// If uint, relocation is assumed by default;  if void*, no relocation is assumed by default.
class TargetPtr {
public:
  /// Conversion constructor for plain pointers.  Defaults to not relocated.
  constexpr TargetPtr(void* pAddress = nullptr, bool relocate = false) : pAddress_(pAddress), relocate_(relocate) { }

  /// Conversion constructor for raw uint addresses.  Defaults to relocated.
  constexpr TargetPtr(uintptr address, bool relocate = true)  :  address_(address),  relocate_(relocate) { }

  /// Conversion constructor for function pointers.  Never relocated.
  template <typename T, typename = Impl::EnableIf<std::is_function<Impl::RemoveCvRefPtr<T>>::value>>
  constexpr TargetPtr(T pfn) : pAddress_((void*)(pfn)), relocate_() { }  // C-style cast due to constexpr quirks.

  /// Conversion constructor for pointers-to-member-functions.  Never relocated.
  /// @note Consider using the MFN_PTR() macro, which is more robust than PmfCast() which backs this constructor.
  template <typename T, typename Pfn, typename = EnableIf<std::is_function<Pfn>::value>>
  TargetPtr(Pfn T::*pmf, const T* pThis = nullptr) : pAddress_((void*)(Util::PmfCast(pmf, pThis))), relocate_() { }

  /// Allow explicit static_cast to any pointer type, similar to void*.
  template <typename T>  explicit constexpr operator T*() const { return static_cast<T*>(pAddress_); }

  constexpr operator      void*() const { return pAddress_; }  ///< Implicit conversion operator to void* pointer.
  constexpr operator    uintptr() const { return  address_; }  ///< Implicit conversion operator to uintptr.
  constexpr bool ShouldRelocate() const { return relocate_; }  ///< Returns if the pointer needs to be relocated.

private:
  union {
    void*   pAddress_;  ///< Address as a pointer.
    uintptr  address_;  ///< Address as a uint.
  };

  bool  relocate_;      ///< Set to true if this is a relocatable address.
};


/// Type erasure wrapper for callable arguments passed to PatchContext.  Can implicitly convert most callables.
/// With non-empty callable types, the object and its lifetime become bound to this and to any patches referencing it.
class FunctionRef {
public:
  template <typename StlFunction> using GetTargetFunc = void*(StlFunction* pStlFunction);  ///< Returns stdfunc.target()

  /// Conversion constructor for void pointers.  Used when referencing e.g. JIT-compiled code.
  constexpr FunctionRef(const void* pFunction) : pfn_(pFunction), sig_(), pObj_(), pState_(), pfnGetInvokers_() { }

  /// Conversion constructor for function pointers.
  template <typename T, typename = EnableIf<std::is_function<T>::value>>
  constexpr FunctionRef(T* pfn)  // C-style cast due to constexpr quirks.
    : pfn_((void*)(pfn)), sig_(FuncTraits<T>{}), pObj_(), pState_(), pfnGetInvokers_() { }

  /// Conversion constructor for pointers-to-member-functions.
  /// @param pThis May be provided to help look up the function address, but that does not bind it to this FunctionRef.
  /// @note Consider using the PATCHER_MFN_PTR() macro, which is more robust than PmfCast() backing this constructor.
  template <typename T, typename Pfn, typename = EnableIf<std::is_function<Pfn>::value>>
  FunctionRef(Pfn T::*pmf, const T* pThis = nullptr)
    : pfn_((void*)(Util::PmfCast(pmf, pThis))), sig_(FuncTraits<Pfn T::*>{}), pObj_(), pState_(), pfnGetInvokers_() { }

  /// Conversion constructor for callable objects.  This works with lambdas, (non-overloaded) functors, etc.
  /// Capturing lambdas or non-empty functor objects will become bound to this FunctionRef using the std::function ctor.
  /// @note To hook T::operator() itself, consider constructing a FunctionRef from &T::operator().
  template <
    typename T, Call C = Call::AbiStd, typename E = typename std::is_empty<T>::type, typename = decltype(&T::operator())>
  constexpr FunctionRef(T&& functor, Util::AsCall<C> call = {}) : FunctionRef(std::forward<T>(functor), call, E{}) { }

  /// Conversion constructor for std::function.
  /// @note std::bind objects must be explicitly wrapped with std::function in order to construct a FunctionRef from it.
  /// @note Conventions that use vector registers (vectorcall, sseregparm, regcall) are currently not supported.
  template <typename R, typename... A, typename Fn = std::function<R(A...)>, Call C = Call::AbiStd>
  FunctionRef(
    std::function<R(A...)> functor, Util::AsCall<C> = {}, GetTargetFunc<decltype(functor)>* pfnGetTarget = nullptr)
    : pfn_(), sig_(FuncSig<R,C,0,A...>{}), pObj_(), pState_(), pfnGetInvokers_(&GetInvokeFunctorTable<Fn, R, A...>::Get)
  {
    InitFunctorThunk(new Fn(std::move(functor)), [](void* p) { delete static_cast<Fn*>(p); });
    pState_ = ((pfnGetTarget != nullptr) && (pObj_ != nullptr)) ? pfnGetTarget(static_cast<Fn*>(pObj_.get())) : nullptr;
  }

  constexpr operator       const void*() const { return pfn_;    }    ///< Implicit pointer conversion, yielding Pfn().
  constexpr const void*            Pfn() const { return pfn_;    }    ///< Gets a pointer to the underlying function.
  constexpr const RtFuncSig& Signature() const { return sig_;    }    ///< Gets function call signature information.
  std::shared_ptr<void>        Functor() const { return pObj_;   }    ///< Gets the functor obj to call with, if any.
  constexpr void*         FunctorState() const { return pState_; }    ///< Gets the functor obj internal state data.
  constexpr auto       InvokerPfnTable() const -> InvokeFunctorTable  ///< Gets the internal functor obj invoker table.
    { return pfnGetInvokers_ ? pfnGetInvokers_() : InvokeFunctorTable{}; }

private:
  template <typename T>  using StlFunctionForFunctor = std::function<typename FuncTraitsNoThis<T>::Function>;
  using PfnGetInvokerTable = InvokeFunctorTable(*)();

  /// Conversion constructor for stateless functors and non-capturing lambdas.
  template <typename T, Call C, typename = decltype(&T::operator())>
  constexpr FunctionRef(T&& functor, Util::AsCall<C>, std::true_type) : FunctionRef(Util::LambdaPtr<C>(functor)) { }

  /// Conversion constructor for state-bound functors and capturing lambdas.
  template <typename T, Call C, typename = decltype(&T::operator()), typename Fn = StlFunctionForFunctor<T>>
  FunctionRef(T&& functor, Util::AsCall<C> call, std::false_type)
    : FunctionRef(Fn(std::forward<T>(functor)), call, [](Fn* pObj) -> void* { return pObj->target<T>(); }) { }

  /// Initializes the thunk for calling InvokeFunctor() with @ref pObj_ (state-bound functor or capturing lambda).
  void InitFunctorThunk(void* pFunctorObj, void(*pfnDeleteFunctor)(void*));

  const void*           pfn_;             ///< Unqualified pointer to the underlying function.
  RtFuncSig             sig_;             ///< Function call signature information about pfn_, if known at compile time.
  std::shared_ptr<void> pObj_;            ///< (State-bound functors) The std::function object bound to pfn_.
  void*                 pState_;          ///< (State-bound functors) Pointer to the state managed by pObj_.
  PfnGetInvokerTable    pfnGetInvokers_;  ///< (State-bound functors) Pointer to the InvokeFunctorTable getter function.
};

/// Template subclass of FunctionRef that can be implicitly converted to a plain function pointer and used as a callable
/// This allows capturing lambdas and state-bound functors to be passed as function pointers of any calling convention.
template <typename T, Call Convention>
class FunctorRef : public FunctionRef {
  using PfnType = AddConvention<typename FuncTraitsNoThis<T>::Function, Convention>;
public:
  /// Conversion constructor for (non-overloaded) functors and lambas, using the cdecl convention by default.
  FunctorRef(T&& f) : FunctionRef(std::forward<T>(f), Util::AsCall<Convention>{}) { }

  /// Gets a type-qualified function pointer to the underlying function.
  PfnType  Pfn()       const { return static_cast<PfnType>(const_cast<void*>(FunctionRef::Pfn())); }
  operator PfnType()   const { return Pfn(); }  ///< Implicit function pointer conversion.  Forwards operator(), *, etc.
  PfnType  operator+() const { return Pfn(); }  ///< Explicit convert to function pointer;  semantics similar to +[]{}.
};


/// Transparent wrapper around a type that has a Register enum value attached to it, allowing for deducing the desired
/// register for the arg for LowLevelHook() at compile time.
template <Registers::Register Id, typename T, uint32 Offset = 0>
class RegisterArg {
  using Type     = RemoveRef<T>;
  using Element  = Conditional<std::is_array<T>::value, RemoveExtents<Type>, RemovePtr<Type>>;
  using DataType = Conditional<std::is_array<T>::value, AddLvalueRef<Type>,  T>;

  static_assert(std::is_reference<T>::value || std::is_array<T>::value || (sizeof(T) <= RegisterSize),
                "Type does not fit in register size.");

public:
  Type& Get()          { return data_; } ///< Explicitly retrieves the underlying data.
  operator Type&()     { return data_; } ///< Implicit conversion operator to a reference of the underlying type.
  operator Type&&() && { return data_; } ///< Implicit conversion operator to a rvalue reference of the underlying type.

  ///@{ In lieu of no "operator.", dereference-like semantics are allowed for all types for struct field access, etc.
  template <typename U = Element> auto operator->() -> EnableIf<std::is_same<U, Type>::value,     U*> { return &data_; }
  template <typename U = Element> auto operator->() -> EnableIf<std::is_same<U, Type>::value ==0, U*> { return  data_; }
  template <typename U = Element> auto operator*()  -> EnableIf<std::is_same<U, Type>::value ==0, U&> { return *data_; }
  template <typename U = Element> auto operator*()  -> EnableIf<std::is_same<U, Type>::value,     U&> { return  data_; }
  ///@}

  template <typename U>  Type& operator=(U&&      src) { return (data_ = std::forward<U>(src)); }  ///< Move-assignment.
  template <typename U>  Type& operator=(const U& src) { return (data_ = src);                  }  ///< Copy-assignment.

  static constexpr Registers::Register RegisterId = Id;  ///< Register associated with this argument.
  static constexpr uint32 StackOffset = Offset;          ///< (Stack only) Offset associated with this argument.

private:
  DataType data_;
};


// =====================================================================================================================
template <typename T, size_t InitialSize>
SmallVector<T, InitialSize>::SmallVector(
  Span<T> src)
  :
  pData_(reinterpret_cast<T*>(&localStorage_[0])),
  numElements_(src.Length()),
  capacity_(InitialSize)
{
  assert(src.Data() != nullptr);

  if (src.Length() > ArrayLen(localStorage_)) {
    // Dynamically allocate storage buffer exceeding InitialSize.
    pData_ = static_cast<T*>(malloc(sizeof(T) * numElements_));
  }

  if (pData_) {
    if (IsPod) {
      memcpy(pData_, src.Data(), src.Length());
    }
    else for (size_t i = 0; i < src.Length(); ++i) {
      new(pData_ + i) T(src[i]);
    }
  }
}

// =====================================================================================================================
template <typename T, size_t InitialSize> template <size_t N>
SmallVector<T, InitialSize>::SmallVector(
  SmallVector<T, N>&& src)
  :
  pData_(reinterpret_cast<T*>(&localStorage_[0])),
  numElements_(src.numElements_),
  capacity_(src.capacity_)
{
  if (static_cast<void*>(src.pData_) != &src.localStorage_[0]) {
    // Take ownership of the dynamic allocation of the ByteArray we're moving from.
    pData_    = src.pData_;
    capacity_ = src.capacity_;
  }
  else if (src.pData_ != nullptr) {
    if (numElements_ > ArrayLen(localStorage_)) {
      // Dynamically allocate storage buffer exceeding InitialSize.
      pData_ = static_cast<T*>(malloc(sizeof(T) * numElements_));
    }

    if (pData_) {
      if (IsPod) {
        memcpy(pData_, src.pData_, numElements_);
      }
      else for (size_t i = 0; i < numElements_; ++i) {
        new(pData_ + i) T(std::move(src.pData_[i]));
        src.pData_[i].~T();
      }
    }
  }
  else {
    pData_        = nullptr;
    numElements_  = 0;
    capacity_     = 0;
  }

  src.pData_        = nullptr;
  src.numElements_  = 0;
  src.capacity_     = 0;
}

// =====================================================================================================================
template <typename T, size_t InitialSize>
bool SmallVector<T, InitialSize>::Reserve(
  size_t newCapacity)
{
  bool result = true;

  if (newCapacity > capacity_) {
    // Dynamically allocate storage buffer.
    T*const pNewData = static_cast<T*>(malloc(sizeof(T) * newCapacity));

    if (pNewData != nullptr) {
      if (IsPod) {
        memcpy(pNewData, pData_, numElements_);
      }
      else for (size_t i = 0; i < numElements_; ++i) {
        new(pNewData + i) T(std::move(pData_[i]));
        pData_[i].~T();
      }

      if (static_cast<void*>(pData_) != &localStorage_[0]) {
        free(pData_);
      }

      pData_    = pNewData;
      capacity_ = newCapacity;
    }
    else {
      result = false;
    }
  }

  return result;
}

// =====================================================================================================================
template <typename T, size_t InitialSize>
bool SmallVector<T, InitialSize>::Append(Span<T> elements) {
  const bool result = Grow(elements.Length());

  if (result) {
    if (IsPod) {
      memcpy(&pData_[numElements_], elements.Data(), elements.Length());
    }
    else for (size_t i = 0; i < elements.Length(); ++i) {
      new(pData_ + i) T(elements[i]);
    }
    numElements_ += elements.Length();
  }

  return result;
}

} // Impl
} // Patcher
