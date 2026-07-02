# User Space Hot Patcher in C

A lightweight, user-space hot patcher for Linux x86_64 that allows injecting code modifications into running processes without restarting them.

## 🚀 Features
* Dynamic code injection using `ptrace` / `LD_PRELOAD` / Function detours (Choose yours).
* Safely updates target functions while maintaining execution state.
* Minimal overhead.

## 🛠️ How It Works
Briefly explain your mechanism so people trust it.
1. **Target Attachment:** Uses `ptrace(PTRACE_ATTACH, ...)` to halt the target process.
2. **State Preservation:** Saves the current CPU registers.
3. **Memory Modification:** Overwrites target function prologues with a `JMP` instruction to the new code.
4. **Resumption:** Restores registers and detaches.

## 📋 Prerequisites
* Linux Kernel 5.x+
* GCC / Clang
* Make / CMake

## 🔧 Building and Running

### 1. Clone and Build
```bash
git clone [https://github.com/yourusername/user-space-hotpatcher.git](https://github.com/yourusername/user-space-hotpatcher.git)
cd user-space-hotpatcher
make