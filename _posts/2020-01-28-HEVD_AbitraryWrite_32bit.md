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
```

We can see that we hit our breakpoint! Awesome, let's actually analyze what this function inside the IOCTL handler, `TriggerArbitraryOverwrite`, is doing now in WinDBG. 

![](/assets/images/AWE/bphit.PNG)

## Analyzing Trigger Arbitrary Overwrite

