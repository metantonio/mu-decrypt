# Technical Report: Bypassing Kernel-Level Memory Protection (Error 5)

## Overview
This report documents the technical challenges and final implementation used to achieve memory writing (injection) in a environment protected by kernel-level security (GameGuard/Anti-Cheat).

## The Challenge: Error 5 (Access Denied)
Standard memory modification using `pymem` or the Windows `WriteProcessMemory` API resulted in a persistent `GetLastError: 5`. This occurred even when the application was running with Administrative privileges.

## Technical Evolution of the Bypass

### 1. Privilege Escalation (`SeDebugPrivilege`)
We implemented logic to enable `SeDebugPrivilege` for our own process. This is a system-level privilege that allows a process intermediate control over other processes, helping overcome basic attachment restrictions.

### 2. Handle Rights Upgrading
Initial handle acquisition was being "stripped" by the security driver. We implemented a multi-stage `OpenProcess` strategy:
- **Phase A**: Request `PROCESS_ALL_ACCESS` (0x1F0FFF).
- **Phase B (Surgical)**: If Phase A fails, request only `VM_WRITE | VM_OPERATION` (0x28). This "minimalist" request often slips past driver-level filters that target intrusive handles.

### 3. Memory Audit & Selective Protection
Using `VirtualQueryEx`, we discovered that some target memory pages were already marked as `PAGE_READWRITE` (0x4), yet writing still failed. This indicated that the security driver wasn't just blocking protection changes, but hooking the high-level writing APIs themselves.

### 4. The Final Solution: NT-Level Bypass
To overcome high-level API hooks in `kernel32.dll` and `kernelbase.dll`, we bypassed these libraries entirely:

- **Bypassing Hooks**: We switched to `ntdll.dll`'s direct system call: `NtWriteVirtualMemory`.
- **Stealth Strategy**: We implemented logic to skip `VirtualProtectEx` whenever `VirtualQueryEx` confirmed the page was already writable. This avoids triggering security drivers that monitor page protection modifications.
- **Direct Kernel Communication**: By speaking directly to the Windows Native API (`ntdll`), we bypassed the filtered gatekeepers of the standard Windows API.

## Conclusion
The combination of **Surgical Handles**, **Selective Protection**, and **NT-Level System Calls** proved successful in overcoming the kernel-level blocks. The memory engine is now capable of modifying game values (like offsets and stats) without being intercepted by the "Access Denied" guard.

---
*Report generated for the Mu-Decrypt Project Dashboard.*
