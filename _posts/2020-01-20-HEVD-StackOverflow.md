---
layout: single
title: HEVD Exploits -- Stack Overflow
date: 2020-01-20
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
Our goal here is to complete an exploit for the HEVD stack overflow vuln on both Win7 x86 and Win7 x86-64. We will follow along closely with the aformentioned blog posts but will try slightly different methods to keep things interesting and to make sure we're actually learning. 

Before this challenge, I had never worked with 64-bit architectures before. I figured an old-fashioned stack overflow would be the best place to start for that, so we'll be completing that part second. 

## Windows 7 x86 Exploit

### Getting Started
HEVD is an example of a [kernel-mode](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-windows-drivers) driver meaning that it runs with kernel/ring-0 privileges. Exploitation of such a service may allow low priviliged users to elevate privileges to `nt authority/system` privileges. 

You'll want to read over some of the [documentation on MSDN](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/), especially the I/O portion, detailing how kernel-mode drivers are architected. 

The [`DeviceIoControl`](https://docs.microsoft.com/en-us/windows/win32/devio/device-input-and-output-control-ioctl-) windows API allows userland applications to communicate directly with a device driver. One of the API's parameters is called an `IOCTL`. This is sort of like a system call from what I can tell that corresponds to certain programmatic functions and routines on the driver. If you send it a code of `1` from userland, for example, the device driver will have logic to parse that `IOCTL` and then execute the corresponding functionality. To interact with our driver, we'll need to use `DeviceIoControl`. 

### `DeviceIoControl`
Let' go ahead and take a look at the prototype API on MSDN:
```cpp
BOOL DeviceIoControl(
  HANDLE       hDevice,
  DWORD        dwIoControlCode,
  LPVOID       lpInBuffer,
  DWORD        nInBufferSize,
  LPVOID       lpOutBuffer,
  DWORD        nOutBufferSize,
  LPDWORD      lpBytesReturned,
  LPOVERLAPPED lpOverlapped
);
```

![](/assets/images/AWE/DriverEntry.PNG)
