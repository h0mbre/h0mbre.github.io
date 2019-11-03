---
layout: single
title: Creating Win32 ROP Chains 
date: 2019-11-02
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Shellcode
  - Windows
  - Assembly
  - Return Oriented Programming 
  - ROP
  - Exploit Development
  - DEP Bypass
---

## Introduction
Continuing with the Windows exploit development our next stop is learning how to craft ROP chains. In the context of this blogpost we will be using them to disable DEP and execute shellcode on the stack; however, ROP chains are extremely versatile and in different contexts can be very powerful. Obviously stack based overflows aren't a very common bug class these days compared to 10 years ago, but this will allow us to use concepts we're familiar with (stack overflows) to learn concepts that are new to us (ROP chains). 

## ROP Chains
ROP stands for Return Oriented Programming. Essentially what we're doing is placing pointers to instructions on the stack, having execution follow those pointers to execute the instructions at that location and then execution returns to the stack to the next pointer. 

The reason this behavior is desirable is because when Data Execution Prevention (DEP) is enabled, we are typically unable to execute code in any section of memory that doesn't explicitly contain executable instructions. This means our traditional stack based overflow attacks won't work as we cannot execute shellcode on the stack. 

This is where the power of ROP comes into play. We uses tiny sections of existing code in the target program that are punctuated in sequence by a `RETN` instruction and piece them together to make a function call which disables DEP. We can then run our shellcode on the stack as we're used to. 

## Required Reading
Corelan has essentially written a manifesto on DEP and Win32 ROP chains [here](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/). Nothing I say or do in this blog is new or groundbreaking, I'm simply recapitulating the ROP learning process for beginners like myself interested in taking their Windows game further and documenting my work for my own reference. 

FuzzySec also has a phenomenal post [here](https://www.fuzzysecurity.com/tutorials/expDev/7.html) as part of their Tutorials series, which also does a great job of walking through the reasoning and logic behind ROP chains.

You need to read and understand these blog posts very well in order to keep up. I will do my best to step through the process with the reader; however, it's always best to consult multiple sources and Corelan and Fuzzy are much more experienced and knowledgeable than I am. 

## Getting Started
In order to save time from scanning through Exploit DB for a suitable PoC and recreating the exploit, I found this [blog post by Steven Patterson](https://www.shogunlab.com/blog/2018/02/11/zdzg-windows-exploit-5.html) and used the same vulnerable program. We will not be consulting the blog post for help on our ROP chain, simply using the same vulnerable program which you can download from [ExploitDB](https://www.exploit-db.com/exploits/40018). Afterwards, we can compare ROP chains and see if there were any areas we could've been more efficient. 

Our starting POC should look something like this: 
```python
import sys
import struct
import os

crash_file = "vuplayer-dep.m3u"

fuzz = "A" * 1012
fuzz += "B" * 4
fuzz += "C" * (3000 - len(fuzz))

makedafile = open(crash_file, "w")
makedafile.write(fuzz)
makedafile.close()
```

This code will create a file `vuplayer-dep.m3u`. Launch the player in Immunity, you'll get some warnings referencing breakpoints, this is normal just click through them. Drag your newly created file into the program GUI and it should crash overwriting EIP with `42424242`. 

Great, we control EIP. Next we need to pass execution the code we're going to overwrite the stack with. For this, we will simply use a `RETN` instruction. We need one that is not ASLR enabled, so let's go ahead and get `mona.py` out and check the modules with a `!mona modules` command. There are several modules in the output which do not have ASLR enabled, namely: `BASSWMA.dll`, `BASSMIDI.dll`, and `BASS.dll`. 

In Immunity, we can right click in the disassembler pane, the top left, and hit `Search for` > `All Commands in all modules` > `RETN` > `Find`. Scroll until you locate a suitable `RETN` instruction in one of the three aformentioned modules. For this blogpost, I will be using the `RETN` located at `0x10101008`. (Go ahead and check it!)

So we input this address into our POC. 

```python
import sys
import struct
import os

crash_file = "vuplayer-dep.m3u"

fuzz = "A" * 1012
fuzz += "\x08\x10\x10\x10" # 10101008  <-- Pointer to a RETN
fuzz += "C" * (3000 - len(fuzz))

makedafile = open(crash_file, "w")
makedafile.write(fuzz)
makedafile.close()
```



