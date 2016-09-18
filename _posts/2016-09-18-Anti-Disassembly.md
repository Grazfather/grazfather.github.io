---
layout: post
title:  "Anti-Disassembly Techniques and Mitigation"
date:   2016-09-18 12:00:00 -0800
categories: re malware ida
---

This is just a small collection of notes about disassembly and anti-disassembly tricks, and how to get around them.

## How disassemblers work
The simplest disassembler is super simple, but they can also be very complicated. More advanced disassemblers try to recognize things like functions (which may have multiples _returns_), idioms like jump tables, and not get tricked by anti-disassembly tricks. They come in two general categories.

1. Linear - Dissassembles all instructions in order, starting from some point (usually the entry point of a binary).
2. Flow-oriented - These follow jumps and calls and continue disassembling from their target. They also might stop disassembling after return instructions, so avoid showing instructions that are unreachable (and thus probably not code at all).

Because flow-oriented disassemblers follow branchesm and because conditional branches exist, the disassembler has to make a decision. Often, for normal code, a disassembler can simply follow both (e.g. jump and don't jump, disassemble from the target and from the next instruction). The problem is that there can be contradictary or incompatible jumps.

## Tricking a flow-oriented disassembler
There are a variety of ways to trick a disassembler. Here are just a few:

1. Put two consecutive, but 'opposite' conditional branches, e.g. a `jz` followed by a `jnz`.
2. Use a constant condition, e.g. `xor eax, eax; jz <addr>`.
3. Use a branch that does nothing, e.g. `call <addr>`, then at _addr_: `pop <reg>`. This is commonly used in shellcode to get an address of in-band data, since on x86 it's the easiest way to get an address around the PC.
4. Use a series of bytes that will be executed more than once, as different instructions, depending where the PC lies. e.g. `EB FF C0 48`. When a disassembler disassembles this (as x86), it'll see `EB FF` as `jmp 1`, then `C0`, which isn't a valid opcode, and finally `48` as `dec eax`.

   The problem is that this isn't how it's executed! the `jmp 1` jumps one byte from the start of the instruction (or rather jumps -1 bytes (0xFF) from the end of the instruction). This makes the EIP land on the 0xFF. Now the CPU decodes `FF C0` as `inc eax` and `48` and `dec eax`. In the end. this code basically does nothing. The solution here: NOP out all four bytes.
5. Abuse `call` and `ret` to mess up function boundaries. e.g. `E8 00 00 00 00 C3`, which is `call 5; ret`. This will push the return address onto the stack, which will be the byte right after the `ret`. The `ret` will then pop off this address into the PC, which effectively makes this two intruction combo useless. However, this cal make the disassembler think that the function ends there and that the next instruction is the end of another function.
6. Heavy use of function pointers. While this can be done without the intent of making the reverse engineer's life more difficult, it has the same effect. Essentially, the address will have cross references to whenever the pointer is copied, but when it is _called_, since it's called from a register or memory address, the disassembler usually can't determine when it's used.

## Mitigation
The most difficult part in getting around these tricks isn't anything to do with patching around them -- That's trivial. The trick is in identifying them quickly and not wasting your time figuring out what they do. That can only be done, really, with practice. Most of all the anti-disassembly I've learned I learned from the amazing book [Practical Malware Analysis](http://www.nostarch.com/malware) in chapter 16. The book includes labs, which I recommend you do. You can see my writeups [here](https://github.com/Grazfather/PracticalMalwareLabs/blob/master/chapter16/readme.md).

Once they're identified, IDA Pro makes it _mostly_ easy to fix. My favourite way to fix them, for the most part, is by using `PatchByte`. This can be done from the 'File > IDC Command...' dialog, and if you don't want to supply the address, you can use `ScreenEA` to use the address of the cursor. This usually looks like `PatchByte(ScreenEA(), 0x90);`. Make sure to run it for each byte you want to remove.

When you know which function is being called from a function pointer (obviously being careful for when more than one function is called from this location) you can add an xref manually using `AddCodeXref`. You'd use is as so `AddCodeXref(ScreenEA(), <addr of function>, fl_CN);`, making sure you've selected the call instruction. You can do the same for jumps, substituting _fl_CN_ for _fl_JN_.
