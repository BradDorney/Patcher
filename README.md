# Patcher

Patcher is a C++11 memory patching and code hooking library that aims to be lightweight yet powerful. It is built around [Capstone](https://www.capstone-engine.org/), a LLVM-based disassembler that itself is lightweight enough to run on embedded systems.

Patcher can be compared to Microsoft's [Detours](https://github.com/microsoft/detours) library, but Patcher possesses some functionality that Detours lacks.

Patcher also has middle-of-function hooking (`LowLevelHook`), that is very user-friendly using normal C++ code instead of raw assembly.

Patcher's features include:
* Insert whole function hooks, with the ability to call the original function, similar to Detours's hook capability (`Hook`)
* Redirect specific function call instructions (`HookCall`)
* Insert instruction-level hooks, with read/write access to registers and the ability to change control flow, with normal C++ code (`LowLevelHook`)
* Edit the module's exports, redirecting them for subsequently-loaded importing modules (`EditExports`)
* Redirect all fixed references to a global variable/object/function (`ReplaceStaticReferences`)
* Overwrite and later restore arbitrary bytes, and both POD and non-POD typed data (`Write<T>`, `WriteBytes`, `WriteNop`)
* Convert capturing lambdas and functors to plain function pointers of any calling convention (`CdeclFunctor`, `StdcallFunctor`, `ThiscallFunctor`, etc.)

Patcher is user-friendly:
* Hook APIs can take lambdas to reduce boilerplate with patching code - one-liners are very practical.
* Target addresses can be passed as raw integers, or as any pointer type, even class method function pointers.
  * Module base relocation is automatically accounted for in target addresses that are passed as raw integers.
* Reverting any or all patches is simple and is automated via RAII - convenient when using Patcher in a hot-pluggable mod environment.


Currently, only x86 (32 and 64-bit), MSVC, and Windows are supported.
There is experimental support for Clang/GCC/ICC in MS ABI mode.  Unix SysV ABI is partially supported.
`LowLevelHook` currently only supports standard general-purpose registers; not float/x87/MMX/SSE/AVX/etc registers yet.

Future updates may include: Python bindings (in progress), full support for other common compilers and ABIs (in progress), patching imports, patching \*nix binaries, extended registers in `LowLevelHook`, and possibly ARM and/or RISC-V support.

# Requirements

* Windows XP or newer
* C++11-capable MSVC, GCC, Clang, ICC, or GCC-compatible compiler
* [Capstone](https://www.capstone-engine.org/) (diet builds supported)

# Included dependencies

* [Xbyak](https://github.com/herumi/xbyak)

# Usage

Patcher's interface is based around `PatchContext` RAII objects.
* Typically, you would declare `PatchContexts` as function-level statics or globals, so that cleanup automatically happens on exit.
* Multiple `PatchContexts` can be used to group together related patches and toggle them separate from each other.
* Each `PatchContext` is associated with one module, but a module can have as many `PatchContexts` as desired.
* Return status after each operation is tracked within the `PatchContext` instance.
  * If an error occurs, all subsequent operations become no-ops until all patches have been reverted.
  * This means that there is no need to check the status after each operation.

Examples of commonly-used interfaces:

```C++
using namespace Patcher::Util;
using namespace Patcher::Registers;

// Constructing a PatchContext with no args targets the base module.
// To target other modules, we could do e.g.  PatchContext("user32.dll"), or  PatchContext("someDLL.dll", true)
// to load (and hold) a reference to the module.
//
// We declare this as a function-level static, so that the patches get reverted when this module gets unloaded.
static Patcher::PatchContext patcher;

// Freeze all other process threads to prevent race conditions between patching and executing.
patcher.LockThreads();

// Insert a code hook replacing a function (and return a function pointer used to call the original function).
static bool(*pfnOldFunction)(int) = nullptr;
patcher.Hook(&SomeFunction, [](int x) -> bool { return pfnOldFunction(x+1); }, &pfnOldFunction);

// Insert a code hook similarly as above, but using a lambda capture to hold the original function pointer.
patcher.Hook(&SomeFunction, SetCapturedTrampoline, [F = &SomeFunction](int x) -> bool { return F(x + 1); });

// Hook a class virtual function using the PATCHER_MFN_PTR() macro to get its address.
//
// Note that while Hook(&SomeClass::SomeFunction, ...) works, PATCHER_MFN_PTR() is more robust for virtual functions.
//
// In this example, we assume the target function uses the thiscall calling convention, so we use the ThiscallFunctor
// util to convert the lambda to use thiscall.
//
// Valid *Functor types include:
// x86-32: StdcalllFunctor,  Fastcall,  Thiscall,    Vectorcall,  Regcall,  Regparm{1,2},  SseRegparm
// x86-64: MscallFunctor,    Unixcall,  Vectorcall,  Regcall
patcher.Hook(
  PATCHER_MFN_PTR(SomeClass::SomeVirtualFunction),
  ThiscallFunctor([](SomeClass* pThis, int x) { pThis->someField_ -= x; }));

// Redirect a function CALL instruction at the specifed code memory address.
// (@ ModuleBase+0x047A8 in this example,  assuming ModuleBase is 0x400000)
patcher.HookCall(0x4047A8, [](void* p, size_t l) -> void { memset(p, 0, l); });

// Insert an instruction-level hook at the specified code memory address (@ ModuleBase+0x18A00 in this example).
// This kind of hook can read & write specified registers, and maybe even changes control flow via return value (addr).
//
// Note: A return value of 0 or void means return to origin.
//       Params of Esp<T&, N> references (esp + N) on the stack.
//       In x64 builds, you would specify registers like e.g. Rax<int64>, Rsi<bool>&, Rsp<int16&, 24>.
patcher.LowLevelHook(0x518A00, [](Eax<int> readableRegister, Esi<bool>& writableRegister, Esp<int16&, 12> stackValue)
  { writableRegister = !writableRegister;  return (readableRegister >= (stackValue++)) ? 0 : 0x518B20; });

// Hook a class virtual function by overwriting its entry in that class's Virtual Function Pointer Table.
// Note: This will not hook the function for subclasses.
int someCapturedLocal = 42;
patcher.Write(0x6E1104 /* Class.vtbl[1] */, ThiscallFunctor([=](T* pThis) { pThis->someField_ -= someCapturedLocal; }));

// Nop out a whole code instruction, at the specified memory address.
patcher.WriteNop(0x5020AE);

// Nop out exactly 12 bytes, at the specified memory address.
patcher.WriteNop(0x628005, 12);

// Write some arbitrary bytes, at the specified memory address.
patcher.WriteBytes(0x481AA4, { 0xC3, 0x90, 0x90 });  // "retn;  nop;  nop"  in x86

// Write some POD data by memcpy.
patcher.Write<int[3]>(0x5F29AC, { -1, 0, 1 });

// Replace static fixed references within the module to a global array, with a larger-sized one of our own.
static int newExtendedGlobalArray[10] = { };  // Expand from int[3] (old size) to int[10] (new size)
patcher.ReplaceStaticReferences(0x608220, sizeof(int[3]), &newExtendedGlobalArray);

// Write some non-POD data by value assignment.
patcher.Assign(0x5FF740, std::vector<int>(20));

// Write some non-POD data by placement new.
patcher.Construct<std::vector<int>>(0x5FF740, 10);

// Revert a previous patch.
patcher.Revert(0x5F29AC);

// Revert all patches.
// Note that this also gets called automatically when the PatchContext is destroyed (why we use a function-level static)
patcher.RevertAll();

// Unfreeze threads previously locked by LockThreads().
patcher.UnlockThreads();

bool success = (patcher.GetStatus() == PatcherStatus::Ok);
```

For more information, see the Doxygen comments in `Patcher.h` and `PatcherUtil.h`.

# Known Issues

* LowLevelHook does not preserve FPU or extended register state.
  * As a workaround, you can explicitly call the XSAV/XRSTOR compiler intrinsics at the start/end of your hook code.

* Stacking multiple patches on the same function/hook address is not fully supported.
  * Workaround: Use multiple PatchContexts, one per stacked hook addr.  Limitations:
     * Either all the patches must be reverted in reverse-chronological order, or the whole process must be restarted, to safely unpatch
     * LowLevelHook has additional limitations:
        * Trying to install inside the middle of any other LowLevelHook patch location (5 bytes), will usually either fail, or otherwise crash.  Installing *exactly* on top of the same patch location will work.
        * Trying a custom return address inside the middle of any patch location (5 bytes), will usually crash.  Returning *exactly* on top of the same patch location will work.

# Projects Using Patcher

* [OPUPatch](https://github.com/OutpostUniverse/OPUPatch) - `Outpost 2: Divided Destiny` community patch

# License

Patcher is licensed under the BSD 3-Clause license.  See `LICENSE` for more information.  Dependencies are distributed under their own licenses.
