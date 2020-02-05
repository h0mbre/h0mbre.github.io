---
layout: single
title: HEVD Exploits -- Windows 7 x86 NULL Pointer Dereference
date: 2020-02-03
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
  - NULL Pointer Dereference
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
+ All of the previous referenced blog posts in the series (obviously I'm reusing code I learned from them every exploit),
+ [\@\_xpn\_'s blog on the same exploit](https://blog.xpnsec.com/hevd-null-pointer/)

Huge thanks to the blog authors.

Also, big thanks to @ihack4falafel for helping me figure out why I was having issues in my last blog post with the 2 byte overwrite of my shellcode buffer. I found a much more reliable way of allocating the buffers in Python this time around and everything worked as planned. 

## Goal
This was a completely new bug class to me, and it was a ton of fun walking through the vulnerability in IDA. For this post, we're going to dissect exactly what is happening by stepping through the routine in WinDBG and tracking our progress in IDA to see how the code paths differ. We're going to finish by completing a reliable exploit script that calls our shellcode allocated in userspace from kernel space and then cleanly returns back to kernel space (the same thing we've been doing!).

## IOCTL
First thing's first, we need to figure out what IOCTL is needed to reach our target routine `TriggerNullPointerDereference`. The function which eventually calls our target function is located in this code block within the `IrpDeviceIoCtlHandler` function in IDA:

![](/assets/images/AWE/idaIOCTL.PNG)

We can see the `call` operation to `NullPointerDereferenceIoctlHandler` which looks like this:

![](/assets/images/AWE/idaIOCTL2.PNG)

Ok, we see the eventual call to `TriggerNullPointerDereference` now, let's go back to `IrpDeviceIoCtlHandler` and determine the IOCTL required to reach this code path. Immediately above our `NullPointerDereferenceIoctlHandler` box, we see the logic detailing the IOCTL parsing.

![](/assets/images/AWE/ioctlparse.PNG)

So we can see that we'll `jz` to our desired code path with an IOCTL of `0x22202b`. Let' script this up and test it. We'll put a breakpoint in with `bp HEVD!TriggerNullPointerDereference` and see if we hit it. Here's our script right now:
```python
import ctypes, sys, struct
from ctypes import *
from ctypes.wintypes import *
from subprocess import *
import sys

kernel32 = windll.kernel32

def interact():
    
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

    buf = "A" * 100
        
    result = kernel32.DeviceIoControl(
        hevd,
        0x22202b,
        buf,
        len(buf),
        None,
        0,
        byref(c_ulong()),
        None
    )

    if result != 0:
        print("[*] Payload sent.")
    else:
        print("[!] Payload failed. Last error: " + str(GetLastError()))

interact()
```

![](/assets/images/AWE/bpnull.PNG)

Everything looks good to go. Let's look at some of our code paths from here in IDA. 

## IDA Breakdown for Noobs by Noob
Looking at the first block of instructions in IDA for the `TriggerNullPointerDereference` function, we can try our best to figure out what's going on. 

![](/assets/images/AWE/sycall.PNG)

Looks like we're pushing a weird constant value onto the stack with `push 6B636148`, so let's look that value up and see if that's some ASCII. Throwing that into an ASCII converter gets us `kcaH`, which is Hack backwards obviously. So that's on the stack now. Next we `push 8` and then `push edi`. 

Early on in the block we see `xor edi, edi` and then its value never changes so we know it's `0` right now. And then we call `ExAllocatePoolWithTag`. So our arguments/parameters for this API call would be: `0`, `8`, and `kcaH`. Let's look up the prototype and see what to make of that:
```c
PVOID ExAllocatePoolWithTag(
  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
  SIZE_T                                         NumberOfBytes,
  ULONG                                          Tag
);
```

So it looks like our `PoolType` is `0`. Finally found some [constant values for this parameter](https://www.vergiliusproject.com/kernels/x86/Windows%208/RTM/_POOL_TYPE) and it looks like this constant is `NonPagedPool`. You can read about paged vs. non-paged memory [here](https://answers.microsoft.com/en-us/windows/forum/all/whats-non-paged-pool-memory/46d33fe6-58d7-4c32-a37b-90b22789fd43). Our next argument is `NumberOfBytes` which we said was `8`. And then finally our `Tag` which is set to `kcaH`. 

So we're allocating 8 bytes of non-paged pool memory with the tag `kcaH`. The last few instructions are also noteworthy:
+ `mov esi, eax`, the return value of the API will be stored in `eax` so we're moving the return value to `esi`
+ `cmp esi, edi`, we know already that `edi` is still `0`, so we're checking if the return value was `0`,
+ `jnz short loc_14E5B`, if the return code is not `0`, we're jumping to the green code path. 

Checking the [MSDN Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag), we see that: *ExAllocatePoolWithTag returns NULL if there is insufficient memory in the free pool to satisfy the request.*

So we're just checking here at the end that the API succeeded. 

Checking out our green codepath here if our API didn't fail, this is our next block of instructions:

![](/assets/images/AWE/2ndblock.PNG)

This is a lot of [DbgPrint](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprint) calls which is kind of cheating, but at the bottom here we see something important. `mov eax, 0BAD0B0B0`. After that, we see a compare being performed with `cmp [ebp+UserValue], eax`. This is easy with all the symbols we're provided but, looks like our 'user provided' value is being compared with `0xBADB0B0`. One thing I did throughout this process was step through every instruction in `TriggerNullPointerDereference` while also consulting this IDA graphical representation of the code paths so I could orient myself. I definitely recommend doing that. 

We can see that we `jnz` if those values do NOT match. So if our user-provided value is not `0xBAD0B0B0`, we're taking this green code path. 

![](/assets/images/AWE/code3.PNG)
