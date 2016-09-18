---
layout: post
title:  "Anti-Debugging Techniques and Mitigation"
date:   2016-09-18 12:00:00 -0800
categories: re malware ida
---

## Techniques
* Windows
  * API methods:
    * `IsDebuggerPresent`
    * `CheckRemoteDebuggerPresent`
    * `NtQueryInformationProcess`
    * `OutputDebugString`/`GetLastError`
  * Manually checking structures
    * Check _BeingDebugged_ in PEB (in fs:[30]).
    * Check _ForceFlags_:
      * In fs:[30][18][10] on Windows XP.
      * In fs:[30][18][44] on Windows 7 32 bit.
    * Check _Flags_:
      * In fs:[30][18][0C] on Windows XP.
      * In fs:[30][18][40] on Windows 7 32 bit.
    * Check _NTGlobalFlag_ at `fs:[30][68] == 0x70`.
    * Look for debuggers specifically:
      * Check registry.
      * Use `FindWindow(<debugger>)`.
      * Look for executables on the file system.
* Linux
  * Check _/proc/self/status_ for _TracerPid_.
  * Try to attach using `ptrace`.

* Generic
  * Check memory for breakpoints (e.g. 0xCC on x86).
  * Code checksums (e.g. CRC).
  * Check timing (see if more time has elapsed between two points than expected, implying single stepping).
    * `rdtsc`.
    * `QueryPerformanceCounter` on Windows.
    * `GetTickCount` on Windows.
  * Mess with the debugger:
    * Use tls callbacks, which run before many debuggers attach (check for a PE's .tls section).
    * Use exception, which are often handled by the debugger, or take too long to be passed to the application..
    * Insert bogus interrupts. e.g. `int 3` (as 0xCC _and_ 0xCD03), `int 2D` (kernel bp), `icebp`.
  * Take advantage of debugger bugs or vulns:
    * Spotify used to crash OllyDBG.
    * Bad PE/ELF.
    * _NumberOfRvaAndSizes_ > 0x10 in _IMAGE_OPTIONAL_HEADER_ crashes OllyDBG 1.1.
    * _SizeOfRawData_ too big in _IMAGE_SECTION_HEADER_ crashes OllyDBG 1.1.
    * Calls to `OutputDebugString` with "%s" token crashes OllyDBG 1.1.

## Mitigation
* There are many plugins for OllyDBG, and newer windows debuggers tend to have them integrated.
* Use hw breakpoints.
* Break on these checks and fake the result.
* Configure the debugger to immediately pass on certain exceptions.
* Use a different debugger.

When all else fails:

* Find where the crash is, find the check and circumvent it.

