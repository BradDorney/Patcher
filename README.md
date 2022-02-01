# Patcher

Patcher is a C++11 memory patching and code hooking library that aims to be lightweight yet powerful. It is built around [Capstone](https://www.capstone-engine.org/), a LLVM-based disassembler that itself is lightweight enough to run on embedded systems. Patcher can be compared to Microsoft's [Detours](https://github.com/microsoft/detours) library, but Patcher possesses some functionality that Detours lacks.

In addition to installing traditional code hooks over whole functions, Patcher is also capable of redirecting specific function call instructions (`HookCall`), and can even insert instruction-level hooks with read/write access to registers and can change control flow (`LowLevelHook`). Patcher can also modify the module's export address table seen by subsequently-loaded importing modules (`EditExports`). Patcher is also able to overwrite arbitrary bytes, and both POD and non-POD typed data. It can also redirect all fixed references to a global variable/object (`ReplaceReferencesToGlobal`), allowing for fixed-size data to be extended.

The interface has a number of conveniences, including: module base relocation is automatically accounted for in target addresses; hook interfaces can take lambdas to help minimize boilerplate in patch code; and reverting any or all patches is simple and is automated via RAII - convenient when using Patcher in a hot-pluggable mod environment.

Currently, only x86 (32 and 64-bit), MSVC, and Windows are supported; there is experimental support for Clang/GCC/ICC in MS ABI mode. `LowLevelHook` currently only supports standard registers.

Future updates may include full support for other common compilers and ABIs, patching imports, patching \*nix binaries, extended registers in `LowLevelHook`, and possibly ARM.

# Requirements

* C++11-capable MSVC, GCC, Clang, ICC, or GCC-compatible compiler
* [Capstone](https://www.capstone-engine.org/) (diet builds supported)

# Usage

Patcher's interface is based around `PatchContext` RAII objects. Typically, you would declare `PatchContexts` as function-level statics or globals, so that cleanup automatically happens on exit. Multiple `PatchContexts` can be used to group together related patches and toggle them separate from each other. Each `PatchContext` is associated with one module, but a module can have many `PatchContexts`. Return status after each operation is tracked within the `PatchContext` object; if an error occurs, all subsequent operations become no-ops until all patches have been reverted.

Examples of commonly-used interfaces:

```C++
using namespace Patcher::Util;
using namespace Patcher::Registers;

// Constructing a PatchContext with no args targets the base module.  To target other modules, we could do e.g.
// PatchContext("user32.dll"), or PatchContext("someDLL.dll", true) to load and hold a reference to the module.
// We declare this as a function-level static so that the patches get reverted when this module gets unloaded.
static Patcher::PatchContext patcher;

// Freeze all other process threads to prevent race conditions between patching and executing.
patcher.LockThreads();

// Insert a code hook replacing a function (and return a function pointer used to call the original function).
static bool(*pfnOldFunction)(int) = nullptr;
patcher.Hook(&SomeFunction, [](int x) -> bool { return pfnOldFunction(x+1); }, &pfnOldFunction);

// Insert a code hook similarly as above, but using a lambda capture to hold the original function pointer.
patcher.Hook(&SomeFunction, SetCapturedTrampoline, [F = (decltype(&SomeFunction))0](int x) -> bool { return F(x+1); });

// Hook a class virtual function using the PATCHER_MFN_PTR() macro to get its address.
// Note that while Hook(&SomeClass::SomeFunction, ...) works, PATCHER_MFN_PTR() is more robust for virtual functions.
//
// In this example, we assume the target function uses the thiscall calling convention, so we use the ThiscallFunctor
// util to convert the lambda to use thiscall.  There is also StdcallFunctor, FastcallFunctor, and VectorcallFunctor.
patcher.Hook(
  PATCHER_MFN_PTR(SomeClass::SomeVirtualFunction), ThiscallFunctor([](SomeClass* pThis, int x) { pThis->someField_ -= x; }));

// Hook a class virtual function by overwriting its vftable entry.  This will not hook the function for subclasses.
int someCapturedLocal = 42;
patcher.Write(0x6E1104, ThiscallFunctor([=](SomeClass* pThis) { pThis->someField_ -= someCapturedLocal; }));

// Redirect a function call instruction.
patcher.HookCall(0x4047A8, [](void* p, size_t l) -> void { memset(p, 0, l); });

// Insert an instruction-level hook which read/writes specified registers and maybe changes control flow via return
// value.  Note that a return value of 0 or void means return to origin.  Esp<T&, N> references (esp + N) on the stack.
// In x64 builds, you would specify registers like e.g. Rax<int64>, Rsi<bool>&, Rsp<int16&, 24>.
patcher.LowLevelHook(0x518A00, [](Eax<int> readableRegister, Esi<bool>& writableRegister, Esp<int16&, 12> stackValue)
  { writableRegister = !writableRegister;  return (readableRegister >= stackValue) ? 0 : 0x518B20; });

// Nop out an instruction.
patcher.WriteNop(0x5020AE);

// Write some arbitrary bytes.
patcher.WriteBytes(0x481AA4, { 0xC3, 0x90, 0x90 });

// Write some POD data by memcpy.
patcher.Write<int[3]>(0x5F29AC, { -1, 0, 1 });

// Write some non-POD data by placement new.
patcher.Construct<std::vector<int>>(0x5FF740, 10);

// Write some non-POD data by value assignment.
patcher.Assign(0x5FF740, std::vector<int>(20));

// Replace fixed references within the module to a global array with a larger-sized one.
static int newExtendedGlobal[10] = { };
patcher.ReplaceReferencesToGlobal(0x608220, sizeof(int[3]), &newExtendedGlobal);

// Revert a previous patch.
patcher.Revert(0x5FF740);

// Revert all patches. Note that this also gets called automatically when the PatchContext is destroyed.
patcher.RevertAll();

// Unfreeze threads previously locked by LockThreads().
patcher.UnlockThreads();

bool success = (patcher.GetStatus() == PatcherStatus::Ok);
```

For more information, see the Doxygen comments in `Patcher.h` and `PatcherUtil.h`.

# Projects Using Patcher

* [OPUPatch](https://github.com/OutpostUniverse/OPUPatch) - `Outpost 2: Divided Destiny` community patch

# License

Patcher is licensed under the BSD 3-Clause license.  See `LICENSE` for more information.
