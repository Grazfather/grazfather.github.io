---
layout: post
title:  "Manual Unpacking"
date:   2016-11-06
categories: re notes
---

While packers' original intention is to minimize the size of a binary, they are often used today as an 'easy' form of obfuscation, making us reverse engineers' lives more difficult. In order to get around them it's important to understand how they work in practice first.

Since writing an application that is intended to be packed is a pain the ass, packing is usually done as a separate step, and most packers can work basically agnostic of the content of what it's packing.

The way packers work is that by creating a binary that 'hijacks' the original entry point of the target binary to instead call an unpacking stub. The packer packs the target binary in some reversible way and hides it in the new binary. The unpacking stub locates the original, packed binary, unpacks it into memory, and finishes by jumping to the _original entry point_ (OEP). Since it's often the intention to hide the imports that the final binary will use, the packer often has to build its own import table and resolve the imports itself: This is prevent a static tool like `readelf` or `CFF Explorer` from getting an idea of the functionality of the original packed binary in its packed form.

Some well-known packers provide tools for unpacking statically or have the technique for unpacking documented somewhere. If you can identify the packer used, it's worth looking for a tool that can unpack it for you. An example of this is [UPX](https://upx.github.io/). Some binaries will use a modified packer, which might fail to unpack with the normal tool, or worse, unpack _incorrectly_. [Flare-on 2015](http://flare-on.com/2015.html) had such a challenge: It seemed to be vanilla UPX, but if you unpacked it using the tool, the challenge was unsolvable.

When it comes to obtaining the unpacked binary, the process usually involves identifying the _OEP_ and stopping once execution has reached that point. This jump is usually refered to as a _tail jump_ (no relation to a tail call).

Once the OEP has been found, the process memory needs to be dumped, the entry point needs to be changed to the OEP (since the unpacking stub probably still exists in the process memory), and the import table needs to be fixed. Luckily there are tools for that. `OllyDump` and `ImpREC` are two such tools, and tutorials on how to use them litter the internet.

## Manual Unpacking Techniques
* Put breakpoints at the end of loops: At this point try to re-analyze the binary for new assembly routines.
* Look for calls that don't return
* Look for jumps with no code after them.
* Look for long jumps that jump into a different section: These can indicate a jump from the unpacking stub and the binary itself.
* Look for `pushad`. Sent a memory breakpoint on these stack addresses, which should break on the corresponding `popad`. These are often used to save the context for `main`.
* Add breakpoints on `GetVersion` or `GetCommandLineA`: These are often called from the normal `main` wrapper that windows compilers add.
  * `GetModuleHandle` for GUI apps.
* Use `gcore` on linux to dump a process's memory once it's been unpacked. This provides a CORE file, which can be openend in gdb or, even better, IDA. Note that the entry point won't have been patched, so this only really helps you with static analysis.
  * You can use `ProcDump` similarly on windows.
* Some more advanced unpacker only unpack 'on demand', meaning that the whole binary is never fully unpacked unless you touch all functionality. This can usually be avoided by scripting your debugger to call the appropriate unpacking routines.
* DLLs can be unpacked, but their exports must remain. `DllMain`, which runs on load, then, contains the unpacker. Make sure to change your debuggers settings to break on _load_ to break early enough to walk through this process.

## Common Packers
* UPX
* PECompact
* ASPack - Use a hardware breakpoint on the stack to easily identify the tail jump.
* Petit - Known to keep one import per library from the original binary to avoid the need to use `LoadLibraryA`.
* WinUpack - Look for a `push`/`retn` combo to jump to the OEP.
* Themida
