---
layout: single
title: HEVD Exploits -- Windows 7 x86 Arbitrary Write
date: 2020-01-28
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Exploit Dev
  - Drivers
  - Windows
  - x86
  - x86-64
  - Shellcoding
  - Kernel Exploitation
  - Write What Where
  - Arbitrary Overwrite
---

## Introduction
Continuing on with the Windows exploit journey, it's time to start exploiting kernel-mode drivers and learning about writing exploits for ring 0. As I did with my OSCE prep, I'm mainly blogging my progress as a way for me to reinforce concepts and keep meticulous notes I can reference later on. I can't tell you how many times I've used my own blog as a reference for something I learned 3 months ago and had totally forgotten. 

This series will be me attempting to run through every exploit on the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). **I will be using HEVD 2.0**. I can't even begin to explain how amazing a training tool like this is for those of us just starting out. There are a ton of good blog posts out there walking through various HEVD exploits. I recommend you read them all! I referenced them heavily as I tried to complete these exploits. Almost nothing I do or say in this blog will be new or my own thoughts/ideas/techniques. There were instances where I diverged from any strategies I saw employed in the blogposts out of necessity or me trying to do my own thing to learn more.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits. 

I used the following blogs as references:
+ All of the blog posts referenced in the [previous post](https://github.com/h0mbre/h0mbre.github.io/blob/master/_posts/2020-01-21-HEVD_Stackoverflow_64bit.md),
+ FuzzySecurity's [tutorial on this very exploit](https://www.fuzzysecurity.com/tutorials/expDev/15.html),
+ GradiusX [exploit code for a similar exploit](https://github.com/GradiusX/HEVD-Python-Solutions/blob/master/Win10%20x64%20v1607/HEVD_arbitraryoverwrite.py),
+ Abatchy's [post on the subject](https://www.abatchy.com/2018/01/kernel-exploitation-7),
+ jNizM [documentation for the SystemInformationModule returned structures](https://gist.github.com/jNizM/ddf02494cd78e743eed776ce6164758f). 

Huge thanks to the blog authors, no way I could've finished these first two exploits without your help/wisdom. 

## Goal
For this post, I will only be concerned with creating a functional exploit. The code will be ugly, but it will work. In the next post, when we port our exploit to x86-64, I will worry about cleaning the code up, utilizing classes to define data structures and maybe even make the portable for both 32 and 64-bit Windows 7. 

## Getting IOCTL with IDA
First and foremost, we need to use IDA to determine the IOCTL code we need to interact with our desired function. This actually isn't that hard this time since we already determined the IOCTL for the overflow last blog post and our new desired function is very close to that one. 

![](/assets/images/AWE/arboverwrite.PNG)

So that's where we want to end up, let's backtrace a few steps and see what we can deduce about the IOCTL.

![](/assets/images/AWE/arbflow.PNG)

This lower box here, is directly connected to our desired function. So in this lower box, if we hit that `jz` opcode, we will end up in our function. You can see that there are two `sub eax, 4` operations that lead to this `jz`. The box immediately out of frame and directly connected to the upper box is actually our `jz` to the stack overflow function. That IOCTL was `0x222003`. So we can summarize the flow as thus:
+ if we subtract `0x222003` from our IOCTL and we don't get `0x0`, 
+ subtract another `0x4`. If we don't get `0x0`,
+ subtract another `0x4`. If we get `0x0`, jump to the Arbitrary Write function.

So we can deduce that `0x222003` + `0x4` + `0x4` is our desired IOCTL. This gives us `0x22200B`. Like we did last post, let's set a breakpoint on our function, send our IOCTL and see if we hit our breakpoint.

Going to pause the debuggee, and rerun our standby commands we always run on our debugger:
+ `sympath\+ <path to the HEVD.pdb file>` <— adds the symbols for HEVD to our symbols path
+ `.reload` <— reloads symbols from path
+ `ed Kd_DEFAULT_Mask 8` <— enables kernel debugging
+ `bp HEVD!ArbitraryOverwriteIoctlHandler` <— sets a breakpoint on our desired function

We'll use this script to send a buffer of 1000 `A` characters. 
```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32

def send_buf():
    hevd = kernel32.CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver", 
        0xC0000000, 
        0, 
        None, 
        0x3, 
        0, 
        None)
    
    if (not hevd) or (hevd == -1):
        print("[!] Failed to retrieve handle to device-driver with error-code: " + str(GetLastError()))
        sys.exit(1)
    else:
        print("[*] Successfully retrieved handle to device-driver: " + str(hevd))

    buf = "A" * 1000
    buf_length = len(buf)
    
    result = kernel32.DeviceIoControl(
        hevd,
        0x22200b,
        buf,
        buf_length,
        None,
        0,
        byref(c_ulong()),
        None
    )

    if result != 0:
        print("[*] Buffer sent to driver successfully.")
    else:
        print("[!] Payload failed. Last error: " + str(GetLastError()))

send_buf()
```

We can see that we hit our breakpoint! Awesome, let's actually analyze what this function inside the IOCTL handler, `TriggerArbitraryOverwrite`, is doing now in WinDBG. 

![](/assets/images/AWE/bphit.PNG)

## Analyzing `TriggerArbitraryOverwrite`
If we look at the debug statements, this is what we get: 
```
kd> g
[+] UserWriteWhatWhere: 0x0187D65C
[+] WRITE_WHAT_WHERE Size: 0x8
[+] UserWriteWhatWhere->What: 0x41414141
[+] UserWriteWhatWhere->Where: 0x41414141
[+] Triggering Arbitrary Overwrite
[-] Exception Code: 0xC0000005
****** HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE ******
```

We sent 1000 A chars, and we see that the `What` we are writing is `0x41414141`. Ok, this seems fine, its obviously taken 4 bytes out of our sent string and is treating them as a 4 byte object to write somewhere. The somewhere is also `0x41414141` as we see it is labeled as the `Where`. Let's step through the function to figure out how this works in the disassembly. 

We'll set a breakpoint on `bp HEVD!TriggerArbitraryOverwrite` and we'll resend the payload. Once we hit our break and then step through a bit we come upon the meat of the function, the highlighted line in the disassembler and the one after it. Let's take a look at these two operations and our register values. 

![](/assets/images/AWE/interesante.PNG)

We can see we're about to execute a `mov eax, dword ptr [edi]` instruction. Looking at the registers, EDI is set currently to `0x41414141`. This operation will definitely fail. There is no mapped memory at `0x41414141` so there is no value there for it to be stored in EAX. This is very different from `mov eax, edi`. What we're doing here is taking a pointer, EDI, and moving the pointer value there to EAX. Very interesting, we can definitely leverage this to write whatever we want I think based on everything we learned last posts. We can simply have EDI point to a pointer that points to our shellcode. 

The next instruction is `mov dword ptr [ebx], eax`. Wow ok, so this will then take that pointer we fed EAX and put it in the memory address EBX is pointing to. We can see from the register values we also control EBX since it's also `0x41414141`. So we not only control what will be written, but where it will be written. Let's go consult the smart people about how to use this to gain code execution. 

Spoiler alert, these two 4-byte groupings are just the first 8 bytes of our buffer. 

## Turning a Read and a Write into Code Execution
After consulting the elders, (blog posts of FuzzySec, Abatchy, etc), we see that a way you can exploit this is to overwrite a function pointer that is called with ring 0 privileges and then invoke that function. Luckily, such a function exists and [this methodology](http://shinnai.altervista.org/papers_videos/ECFID.pdf) is pretty seasoned at this point. 

I'm not going to spend a bunch of time explaining the underlying concepts here, the referenced blog posts do a great job of that. Please go read them, at a bare minimum read the FuzzySec and Abatchy blogs. At a high-level, we will use a routine within the `HalDispatchTable` (an abstraction layer for hardware interactions), `HaliQuerySystemInformation`, which is rarely used.

This function resides at offset `0x4` within the `HalDispatchTable`. Abatchy breaks it down as follows:
```
kd> dd HalDispatchTable     
82970430  00000004 828348a2 828351b4 82afbad7
82970440  00000000 828455ba 829bc507 82afb3d8
82970450  82afb683 8291c959 8295d757 8295d757
82970460  828346ce 82834f30 82811178 82833dce
82970470  82afbaff 8291c98b 8291caa1 828350f6
82970480  8291caa1 8281398c 8281b4f0 82892c8c
82970490  82af8d7f 00000000 82892c9c 829b3c1c
829704a0  00000000 82892cac 82af8f77 00000000

kd> ln 828348a2 
Browse module
Set bu breakpoint

(828348a2)   hal!HaliQuerySystemInformation   |  (82834ad0)   hal!HalpAcpiTimerInit
Exact matches:
    hal!HaliQuerySystemInformation (<no parameter info>)
```






