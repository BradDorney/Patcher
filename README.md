# Patcher

Patcher is a C++11 memory patching and code hooking library that aims to be lightweight yet powerful. It is built around [Capstone](https://www.capstone-engine.org/), a LLVM-based disassembler that itself is lightweight enough to run on embedded systems. Patcher can be compared to Microsoft's [Detours](https://github.com/microsoft/detours) library, but Patcher possesses some functionality that Detours lacks.

Patcher's features include:
* Insert whole function hooks, with the ability to call the original function, similar to Detours's hook capability (`Hook`)
* Redirect specific function call instructions (`HookCall`)
* Insert instruction-level hooks, with read/write access to registers and the ability to change control flow (`LowLevelHook`)
* Edit the module's exports, redirecting them for subsequently-loaded importing modules (`EditExports`)
* Redirect all fixed references to a global variable/object/function (`ReplaceReferencesToGlobal`)
* Overwrite and later restore arbitrary bytes, and both POD and non-POD typed data (`Write`, `WriteBytes`, `Construct`)

The interface has a number of conveniences, including:
* Hook interfaces can take non-capturing lambdas, and cast to any calling convention, to help minimize boilerplate in patch code.
  * `dev` branch includes experimental support for capturing lambdas and functors.
* Target addresses can be passed as raw integers or as any pointer type.
  * Module base relocation is automatically accounted for in target addresses that are passed as integers.
* Reverting any or all patches is simple and is automated via RAII - convenient when using Patcher in a hot-pluggable mod environment.

Currently, only x86-32, MSVC, and Windows are supported; there is experimental support for Clang/GCC/ICC in MS ABI mode. `LowLevelHook` currently only supports standard registers.
* `dev` branch includes experimental x86-64 support.

Future updates may include Python bindings, full support for other common compilers and ABIs, patching imports, patching \*nix binaries, extended registers in `LowLevelHook`, x86-64, and possibly ARM.

# Requirements

* Windows XP or newer
* C++11-capable MSVC, GCC, Clang, ICC, or GCC-compatible compiler
  * C++17 is required for full use of `PmfCast` (`dev` branch removes this requirement)
* [Capstone](https://www.capstone-engine.org/) (diet builds supported)

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
using namespace Patcher;

// Constructing a PatchContext with no args targets the base module.  To target other modules, we could do e.g.
// PatchContext("user32.dll"), or PatchContext("someDLL.dll", true) to hold a reference to the module.
// We declare this as a function-level static so that the patches get reverted when this module gets unloaded.
static PatchContext patcher;

// Lock all other process threads to prevent race conditions between patching and executing.
patcher.LockThreads();

// Insert a code hook replacing a function (and return a function pointer used to call the original function).
static bool(*pfnOldFunction)(int) = nullptr;
patcher.Hook(&SomeFunction, [](int x) -> bool { return pfnOldFunction(x + 1); }, &pfnOldFunction);

// Hook a class virtual function using the MFN_PTR() macro to get its address.
//
// In this example, we assume the target function uses the thiscall calling convention, so we use the ThiscallLambdaPtr
// util to convert the lambda to use thiscall.  There is also StdcallLambdaPtr, FastcallLambdaPtr, VectorcallLambdaPtr.
patcher.Hook(
  MFN_PTR(SomeClass::SomeVirtualFunction), ThiscallLambdaPtr([](SomeClass* pThis, int x) { pThis->someField_ -= x; }));

// Redirect a function call instruction.
patcher.HookCall(0x4047A8, [](void* p, size_t l) -> void { memset(p, 0, l); });

// Insert an instruction-level hook which read/writes specified registers and maybe changes control flow via return
// value.  Note that a return value of 0 means return to origin.
patcher.LowLevelHook(0x518A00, [](Eax<int> readableRegister, Esi<bool>& writableRegister)
  { writableRegister = !writableRegister;  return (readableRegister >= 1) ? 0 : 0x518B20; });

// Write some arbitrary bytes.
patcher.WriteBytes(0x481AA4, { 0xC3, 0x90, 0x90 });

// Write some POD data.
patcher.Write<int[3]>(0x5F29AC, { -1, 0, 1 });

// Write some non-POD data.
patcher.Construct<std::vector<int>>(0x5FF740, 10);

// Replace fixed references within the module to a global array with a larger-sized one.
static int newExtendedGlobal[10] = { };
patcher.ReplaceReferencesToGlobal(0x608220, sizeof(int[3]), &newExtendedGlobal);

// Revert a previous patch.
patcher.Revert(0x5FF740);

// Revert all patches. Note that this also gets called automatically when the PatchContext is destroyed.
patcher.RevertAll();

// Unlock threads previously locked by LockThreads().
patcher.UnlockThreads();

bool success = (patcher.GetStatus() == Status::Ok);
```

For more information, see the Doxygen comments in `Patcher.h` and `PatcherUtil.h`.

# Projects Using Patcher

* [OPUPatch](https://github.com/OutpostUniverse/OPUPatch) - `Outpost 2: Divided Destiny` community patch

# License

Patcher is licensed under the BSD 3-Clause license.  See `LICENSE` for more information.
