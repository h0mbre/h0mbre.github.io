---
layout: single
title: HEVD Exploits -- Windows 7 x86-64 Uninitialized Stack Variable
date: 2020-02-09
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Exploit Dev
  - Drivers
  - Windows
  - x86
  - Shellcoding
  - Kernel Exploitation
  - Uninitialized Stack Variable
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

## HEVD Series Change
I will no longer be using Python ctypes to write exploits. We will be using C++ from now on. I realize this is a big change for people following along so I've commented the code heavily. 

I will no longer be doing x86 exploits, only x86-64 from now on. 

## Goal
This one is pretty straightforward, we'll be attacking HEVD as normal, this time looking at the uninitialized stack variable bug class. While this isn't super common (I don't think?), there is a very neat API we can leverage from userland to spray the kernel stack and set ourselves up nicely so that we can get control over a called function pointer value. 

## IOCTL Things

Call graph for our desired function:

![](/assets/images/AWE/svioctl.PNG)

We will be targeting a vulnerable function that triggers an uninitialized stack variable vulnerablity. We can see from the `IrpDeviceIoCtlHandler` function in IDA that we branch to our desired call in the bottom left after failing a `jz` after comparing our IOCTL value (`eax`) with `0x22202B` and then subtracting another `0x4` and successfully triggering a `jz`. So we can conclude that our desired IOCTL is `0x22202B` + `0x4`, which is `0x22202F.`

We'll write some code that creates a handle to the driver and sends a phony payload just to see if we break on that memory location as anticipated. 

You'll notice from our image above that the targeted block of instructions is denoted by a location of `loc_16A27`. We'll go the more realistic route here and pretend we don't have the driver symbols and just set a breakpoint on the loaded module name `HEVD` (if you're confused about this, enter `lm` to check the loaded modules in `kd>` and take a gander at the list), and then add a breakpoint at `!HEVD+0x6a27`, the `1` in the location is actually assuming a base address of  `0x0000000000010000`, so we can remove that and dynamically set the breakpoint at the offset. (I think?) BP is set, let's run our code and see if we hit it, we'll send a junk payload of `AAAAAAAA` right now for testing purposes. 

Our code will look like this at this point:
```cpp
```

![](/assets/images/AWE/wehit.PNG)

As you can see, we hit our breakpoint so our IOCTL is correct. Let's figure out what this function actually does. 
