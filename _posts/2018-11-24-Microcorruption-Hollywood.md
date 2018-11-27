---
layout: post
title:  "Microcorruption Hollywood"
date:   2018-11-24-12:00:00 -0800
categories: ctf re
---
I'm a _few_ years late to the party here, but I've recently managed to finish [Microcorruption](http://microcorruption.com). I had finished most of the challenges back in 2014, when they were released, but not having IDA back then, I was stumped when the first challenge that relocated showed up, because it broke the online disassembler, and I was helpless without it :).

I recently took another look, having picked up some skill and knowledge in the intervening years. _Hollywood_, the last challenge, was a very interesting challenge, and I found that most writeups I found online glossed over the difficulty of getting something coherent out of it, so I figured I would try to add a writeup that goes into more detail.

The challenge is a simple prompt for the password, and the CPU just halts on improper input. Looking at the disassembly output was useless, since the web disassembler just disassembles linearly, and they used jumps to jump over a few, uesless bytes, but these bytes were disassembled as six-byte opcodes, hiding the actual instruction.

Linear web disassembly:
{% highlight asm %}
4400:  013c           jmp       #0x4404 <main+0x4>
4402:  d1a1 3140 0044 dadd.b    0x4031(sp), 0x4400(sp)
4408:  013c           jmp       #0x440c <main+0xc>
440a:  d1a1 1542 5c01 dadd.b    0x4215(sp), 0x15c(sp)
{% endhighlight %}

IDA's disassembly:
{% highlight asm %}
ROM:00004400 ; ---------------------------------------------------------------------------
ROM:00004400                 jmp     loc_4404
ROM:00004400 ; ---------------------------------------------------------------------------
ROM:00004402                 .byte 0D1h
ROM:00004403                 .byte 0A1h
ROM:00004404 ; ---------------------------------------------------------------------------
ROM:00004404
ROM:00004404 loc_4404:                               ; CODE XREF: ROM:00004400↑j
ROM:00004404                 mov.w   #4400h, SP
ROM:00004408                 jmp     loc_440C
ROM:00004408 ; ---------------------------------------------------------------------------
ROM:0000440A                 .byte 0D1h
ROM:0000440B                 .byte 0A1h
ROM:0000440C ; ---------------------------------------------------------------------------
{% endhighlight %}

Using a script I found online, I was able to convert the memory dump into a binary blob, which I could then import into IDA, selecting Texas Instrument MSP430 as the CPU type. Following through this code you see that the code relocates and seems to unpack. No problem, I just ran it in the web debugger until it prompted me for input, then I copied _that_ memory dump, created a new binary, and analyzed that in IDA.

There were two problems with this approach. First, it used the `rand` syscall, so where the code was unpacked to was non-deterministic, and would change between runs. This meant that I couldn't follow along in both IDA and the web disassembler. The second problem was that the program seems to relocate again. Stepping through until it jumps to the next spot, I figured I could just generate another dump when the program was fully unpacked. I generated a new binary, stepped through that, generated another, stepped through that... I did this twelve times before I figured out that there was probably no end in sight. Time to bust out the tooling.

I found a [MSP430 emulator](https://github.com/cemeyer/msp430-emu-uctf), specifically one that implements all the idiosyncrasies and syscalls of the Microcorruption MSP430. I could run the original dumped rom through this and generate a trace, then I could use another [python script](https://github.com/Cixelyn/msp430-trace-disassembler) to disassemble the trace. Problem: the trace was over half a million instructions, and since it's just a disassembly listing, I had to look at it linearly.

Figuring that this was a multi-stage unpacker, I had another idea: I would modify the emulator to write every executed instruction to a binary file, at the address of its PC. The goal being to end up with a rom that has each stage of the unpacker present. Since I was not committing writes to the file, but instead just what was executed, I would not wipe out old stages. A simple change to the emulator to create a sparse file, then for each instruction executed, seek to the PC, and write the opcode bytes to the file accomplished this goal.

Now with this full ROM I could get to reverse engineering the code that matters. Popping the binary into IDA showed an unpacking stage at 0x4400 (The entry point), 0x5000, and 0x8000. These nice addresses led me to figure out that my emulator always returned zero from the `rand` syscall, definitely convenient. When running on the online debugger the stages were scattered somewhere on each of these pages.

Reversing the binary was mostly straight forward in IDA, since it isn't a linear sweep disassembler it wasn't tricked by jumps into instructions. There were many basic blocks that apparently had no path to them, but that was because of another trick: Instead of calling a function, they would push PC, branch to the function, then pop the PC, increment it, and jump back to it, effectively returning to where it had started. IDA didn't recognize this, but it just meant that the control flow returned to the next basic block.

{% highlight asm %}
ROM:00004508 ; ---------------------------------------------------------------------------
ROM:00004508                 mov.w   R15, 8(R12)
ROM:0000450C                 mov.w   @R10+, R15
ROM:0000450E                 push.w  PC
ROM:00004510                 jmp     loc_45BE        ; Basically a call
ROM:00004512 ; ---------------------------------------------------------------------------
ROM:00004512                 mov.w   R15, 0Ah(R12)
ROM:00004516                 mov.w   @R10+, R15
ROM:00004518                 push.w  PC
ROM:0000451A                 jmp     loc_45BE        ; Basically a call
...
ROM:0000460A loc_460A:                               ; CODE XREF: sub_4400+206↑j
ROM:0000460A                 pop     R14             ; Pop the PC that was pushed earlier
ROM:0000460C                 incd.w  R14             ; Increment it to the next instruction
ROM:0000460E                 jmp     loc_4612
ROM:0000460E ; ---------------------------------------------------------------------------
ROM:00004610                 .byte    0
ROM:00004611                 .byte    0
ROM:00004612 ; ---------------------------------------------------------------------------
ROM:00004612
ROM:00004612 loc_4612:                               ; CODE XREF: sub_4400+20E↑j
ROM:00004612                 br      R14             ; Return
{% endhighlight %}

Reversing these three 'unpackers' showed about the same thing: It would copy some bytes to a random location, decrypt them, and then ultimately jump to them, then finally return and wipe out the instructions - Lucky for me I could see these ephemeral instructions because, remember, I only write _executed_ bytes to the rom file, not written bytes. Whenever a stage of the unpacker was done, it would jump to `eXXX`, where XXX is `rand & 0xFFE`. Because the emulator always returned 0 from the `rand` syscall, this was always exactly `0xe000`. That meant that the few instructions at 0xe000 weere just the _last_ few that executed, and I was missing the actual code.

Taking a step back, I realized that everything I had reversed was only the unpacked. There was no hint of the prompt or the password validation. Staring at this for some time it hit me: This isn't an unpacker, it's more of a VM! A few instructions are unpacked, jumped to, wiped out, and then this is repeated. _Everything_ that mattered was executed at 0xeXXX.

Back to the emulator, I made another modification that prepended every opcode trace with the address it executes at, and then I modified the disassembler to account for this and print the line with the PC preceding it. I then filtered the output to only keep any address that started with 0xeXXX.

Boom! Down from half a million instructions to a few hundred! I can reverse this.

{% highlight asm %}
e000   9E1C: 3182      sub    #8, SP
e002   9E1D: 3C40 EA49 mov    #0x49ea, R12
e006   9E1E: 004D      br     R13
e4c6   A5B5: 3240 0080 mov    #0x8000, SR
e4ca   A5B6: 3C40 CA48 mov    #0x48ca, R12
e4ce   A5B7: 004D      br     R13
e000   AD4D: B140 5700 0600 mov    #0x57, 0x6(SP)
e006   AD4E: 3C40 8448 mov    #0x4884, R12
e00a   AD4F: 004D      br     R13
e000   B4E6: B012 1000 call   #0x10
e004   B4E8: 3C40 584D mov    #0x4d58, R12
e008   B4E9: 004D      br     R13
e000   BC7F: B140 6800 0600 mov    #0x68, 0x6(SP)
e006   BC80: 3C40 9C45 mov    #0x459c, R12
e00a   BC81: 004D      br     R13
...
{% endhighlight %}

That's more fucking like it. The `br R13` is just the return to the unpacker, and the `mov #0xXXXX, R12` was just another address used for unpacking. Filter them out!

{% highlight asm %}
e000   9E1C: 3182      sub    #8, SP
e4c6   A5B5: 3240 0080 mov    #0x8000, SR
e000   AD4D: B140 5700 0600 mov    #0x57, 0x6(SP)
e000   B4E6: B012 1000 call   #0x10
e000   BC7F: B140 6800 0600 mov    #0x68, 0x6(SP)
e000   C418: B012 1000 call   #0x10
e000   CBB1: B140 6100 0600 mov    #0x61, 0x6(SP)
e000   D34A: B012 1000 call   #0x10
e000   DAE3: B140 7400 0600 mov    #0x74, 0x6(SP)
e000   E27C: B012 1000 call   #0x10
e000   EA15: B140 2700 0600 mov    #0x27, 0x6(SP)
e000   F1AE: B012 1000 call   #0x10
e000   F947: B140 7300 0600 mov    #0x73, 0x6(SP)
e000  100E0: B012 1000 call   #0x10
e000  10879: B140 2000 0600 mov    #0x20, 0x6(SP)
e000  11012: B012 1000 call   #0x10
e000  117AB: B140 7400 0600 mov    #0x74, 0x6(SP)
e000  11F44: B012 1000 call   #0x10
e000  126DD: B140 6800 0600 mov    #0x68, 0x6(SP)
e000  12E76: B012 1000 call   #0x10
...
{% endhighlight %}

What we are seeing here is the prompt "What's the password?" being printed, one character at a time. After this is the validation:

{% highlight asm %}
...
B140 0026 0600 mov    #0x2600, 0x6(SP)
B140 0001 0800 mov    #0x100, 0x8(SP)
3240 0082      mov    #0x8200, SR
B012 1000      call   #0x10
3540 0026      mov    #0x2600, R5
0643           clr    R6

repeats 8 times {
2455           add    @R5, R4
8410           swpb   R4
36E5           xor    @R5+, R6
06E4           xor    R4, R6
04E6           xor    R6, R4
06E4           xor    R4, R6
8593 0000      tst    0x0(R5)
0742           mov    SR, R7
27F3           and    #2, R7
0711           rra    R7
17E3           xor    #1, R7
8710           swpb   R7
0711           rra    R7
8711           sxt    R7
8710           swpb   R7
8711           sxt    R7
3840 184B      mov    #0x4b18, R8
08F7           and    R7, R8
37E3           xor    #-1, R7
37F0 AA47      and    #0x47aa, R7
0857           add    R7, R8
0743           clr    R7
}

3490 B1FE      cmp    #0xfeb1, R4
0742           mov    SR, R7
0443           clr    R4
3690 9892      cmp    #0x9298, R6
07F2           and    SR, R7
0643           clr    R6
0711           rra    R7
17E3           xor    #1, R7
8710           swpb   R7
0711           rra    R7
0711           rra    R7
0711           rra    R7
0711           rra    R7
02D7           bis    R7, SR
{% endhighlight %}


Using this filtered output, I got the original bytes and converted them back to a binary that was only 732 bytes and running this in the emulator worked! That confirmed that I filtered it down to exactly what I needed.
Looking at this tiny assembly it's easy to see what's happening: Two bytes of the input are checked at a time, and they are mixed into R4, R6, and R8. After the loop runs eight times, the value of R4 and R6 is checked, and then the status register is copied to R7, rotated around, and written back to SR. This is why the CPU was halting: The SR was set to some bogus value. We want 0x7F00 in R7 on the last instruction. The comparison to 0xfeb1 sets the status bits, and to preserve them they have to survive the AND with the status register after the comparison to 0x9298. This means that we need R4 and R6 to equal these values after the loop, meaning everything to do with R7 and R8 in the loop is trash!

{% highlight asm %}
B140 0026 0600 mov    #0x2600, 0x6(SP)
B140 0001 0800 mov    #0x100, 0x8(SP)
3240 0082      mov    #0x8200, SR
B012 1000      call   #0x10
3540 0026      mov    #0x2600, R5
0643           clr    R6

repeats 8 times {
2455           add    @R5, R4
8410           swpb   R4
36E5           xor    @R5+, R6
06E4           xor    R4, R6
04E6           xor    R6, R4
06E4           xor    R4, R6
}

3490 B1FE      cmp    #0xfeb1, R4
0742           mov    SR, R7
0443           clr    R4
3690 9892      cmp    #0x9298, R6
07F2           and    SR, R7
...
{% endhighlight %}

That's very reasonable. I was able to convert this to python easily:

{% highlight python %}
r4 = 0
r6 = 0
for i in range(8):
    r4 = (r4 + u16(s[i*2:i*2+2]) & 0xFFFF)
    r4 = swpb(r4)
    r6 ^= u16(s[i*2:i*2+2])
    r4, r6 = r6, r4
{% endhighlight %}

I tried bruteforcing this, but with a 16 byte input this was not happening. Time for z3!

{% highlight python %}
password = [BitVec("s0", 16), BitVec("s1", 16), BitVec("s2", 16), BitVec("s3", 16),
            BitVec("s4", 16), BitVec("s5", 16), BitVec("s6", 16), BitVec("s7", 16)]
r4 = BitVecVal(0, 16)
r6 = BitVecVal(0, 16)
for i in range(8):
    r4 = r4 + password[i]
    r4 = RotateRight(r4, 8)
    r6 ^= password[i]
    r4, r6 = r6, r4

solver = Solver()

# Add constraints
solver.add(r4 == 0xfeb1)
solver.add(r6 == 0x9298)

# Solve
solver.check()
m = solver.model()
{% endhighlight %}

Then simply converting the solution from 8 16-bit integers to a byte string, and submitting that, I was treated to that delicious win.
