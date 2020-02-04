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

