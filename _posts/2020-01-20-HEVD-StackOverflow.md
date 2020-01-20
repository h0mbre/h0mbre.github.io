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

As you can see, `hDevice` is going to be a handle to our driver. We will need to use a separate API called [`CreateFileA`](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) to open a handle to our driver. Let's take a look at that prototype:
```cpp
HANDLE CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);
```

Typically, when interacting with these APIs you'd be writing applications in C or C++; however, we're going to be using Python with the help of a library called `ctypes`, which allows us to utilize several fine-grained data typing features of C. There's several ways of satisfying the parameters of `CreateFileA`; but we will be using hex codes. (I should also mention that we are using Python2.7 because I hate messing with the new `str` and `byte` data types in Python3 during exploit code development. Please don't yell at me. Also, if you were to port this to Python3, please be aware that these Windows APIs expect certain string encoding formats. `CreateFileA` will fail if you do not account for the fact that Python3 treats strings as Unicode.)

I'll explain a couple of the parameters that I think need explaining and then I will leave the remainder to the sleuthing of the reader. It's important to not just be spoon fed these values and actually track down their meaning. I'm familiar with some of the APIs just by virtue of having done some intro-level shellcoding on Windows, but I'm far from an expert. I find it's most useful to track down examples of the API calls and see what they look like in code.

The first value we need is the `lpFileName` value. We have access to the HEVD source code and could find it there; however, I think it's better to approach this as if the source code was a black box to us. We will open the `.sys` file in IDA Free 7.0 and see if we can track it down. 

Once you open the file in IDA, you should be directed to the DriverEntry function. 
![](/assets/images/AWE/DriverEntry.PNG)

As you can see, there is string right in this first function that has our `lpFileName`, `\\Device\\HackSysExtremeVulnerableDriver`. This will be formatted as `"\\\\.\\HackSysExtremeVulnerableDriver"` in our Python code. You can google to find out more about this value and how to format it. 

Next, is the `dwDesiredAccess` parameter. In Rootkit's [blog](https://rootkits.xyz/blog/2017/08/kernel-stack-overflow/) we see that he has used the value `0xC0000000`. This can be explained by checking the [Access Mask Format](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format?redirectedfrom=MSDN) documentation and looking up the corresponding potential values. We see that the most significat bit (most left) is set to `C` or `12` in decimal. We can look at [`winnt.h`](https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-tools/widl/include/winnt.h) to determine what this constant could mean. We see here that `GENERIC_READ` and `GENERIC_WRITE` are `0x80000000` and `0x40000000` respectively. `0xC0000000` is simply these two added together. It's actually intuitive! Wow!

I think you can figure out the other parameters. At this point, our `CreateFileA` and our exploit code looks like this:
```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32

def create_file():

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
        return hevd
 ```
 
 From the documentation, `CreateFileA` returns a handle to our device if successful and will give us an error code if it fails. We now have our handle, and we can finish our `DeviceIoControl` call. 
 
 #### IOCTLs
 
 The next thing we need after the handle (`hevd`), is our `dwIoControlCode`. Just a tip, if you see IOCTLs in IDA there's a good chance they are in decimal. This is a great [RE Stack Exchange](https://reverseengineering.stackexchange.com/questions/15283/ioctl-code-for-windows-driver) post which explains all of the nuance. 
 
