---
layout: post
title:  "Obfuscation Techniques"
date:   2016-10-12 12:00:00 -0800
categories: re notes
---

I don't know where I got these notes from, but I found them on my evernote and I thought they were worth exporting here.

# Data-based obfuscation
* Constant Unfolding
  * A compiler would do something like replace x = 4 * 5 with x = 20. This does the opposite.
    * e.g. `push 0F9CBE47ah, add dword ptr [esp], 6341B86h`. This is effectively `push 0h`.
* Dead Code Insertion
  * Simply add code that has no effect but wastes the reverse engineer's time.
* Arithmetic Substitution via Identities
  * Replace simple things (e.g. `not eax`) with a more complicated form with the same functionality (`xor eax, 0FFFFFFFFh`).
* Pattern-Based Obfuscation
  * Map one or more instructions to a more complicated sequence of instructions that are semantically equivalent. Can be run multiple times.

# Control-based obfuscation
Break the assumptions that reverse engineers have made on how compilers work.

* CALLs return, exceptions are used for exceptional cases, etc.
* Functions In/Out-Lining
  * Inline some functions, break other sections into their own functions so that the call graph doesn't make sense.
* Destruction of Sequential and Temporal Locality
  * `jmp` everywhere.
  * Easy for disassemblers to line up, but harder for people.
* Processor-Based Control Indirection
  * e.g. `push <addr>, ret` to simulate `jmp <addr>`.
  * Use `call` as `jmp`:

    ```asm
    call target_addr
    <junk code>
    target_addr:
    add esp, 4 ; get rid of RA on stack
    ```

  * Modify RA on stack:

    ```asm
    basic_block_a:
    add [esp], 9
    ret
    ...
    basic_block_b:
    call basic_block_a
    <junk code>
    true_return_addr:
    ...
    ```

* Operating-System-Based Control Indirection
  * e.g. use SEH by adding a handler and then causing an exception.
    * Can be good for anti-debug, since debuggers often catch these. Target program can count on its own handler running and detect when the debugger does instead.
* Opaque Predicates
  * Add spurious alternate branches to unconditional jumps.
  * Add two branches that are semantically identical but obfuscated differently.

# Simultaneous Control-flow and Data-flow obfuscation
* Inserting Junk Code
* Control-Flow Graph Flattening
  * Use a 'dispatcher' that maintains state and takes different branches based on current state, so relationships between basic blocks are hidden in the implementation of the dispatcher.
* Virtual Machines
  * Use a VM to run virtualized code.
* White Box Cryptography
  * White-box attack context: An attacker model that assumed an attacker (reverse engineer) can execute the app in an environment that he or she perfectly controls.
