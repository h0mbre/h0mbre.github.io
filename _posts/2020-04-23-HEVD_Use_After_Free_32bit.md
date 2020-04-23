---
layout: single
title: HEVD Exploits -- Windows 7 x86 Use-After-Free
date: 2020-04-23
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
  - UAF
---

## Introduction
Continuing on with my goal to develop exploits for the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). **I will be using HEVD 2.0**. There are a ton of good blog posts out there walking through various HEVD exploits. I recommend you read them all! I referenced them heavily as I tried to complete these exploits. Almost nothing I do or say in this blog will be new or my own thoughts/ideas/techniques. There were instances where I diverged from any strategies I saw employed in the blogposts out of necessity or me trying to do my own thing to learn more.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits.

## Thanks
- To [@r0oki7](https://twitter.com/r0otki7) for their [walkthrough,](https://rootkits.xyz/blog/2018/04/kernel-use-after-free/)
- To [@FuzzySec](https://twitter.com/FuzzySec) for their [walkthrough,](http://www.fuzzysecurity.com/tutorials/expDev/19.html)

## UAF Setup
I've never exploited a use-after-free bug on any system before. I vaguely understood the concept before starting this excercise. We need what, in my noob opinion, seems like quite a lot of primities in order to make this work. Obviously HEVD goes out of its way to be vulnerable in precisely the correct way for us to get an exploit working which is perfect for me since I have no experience with this bug class and we're just here to learn. I feel like although we have to utilize multiple functions via IOCTL, this is actually a more simple exploit to pull off than the pool overflow that we just did. 

Also, I wanted to do this on 64 bit; however, most of the strategies I saw outlined required that we use `NtQuerySystemInformation`, which as far as I know requires your process to be elevated to an extent so I wanted to avoid that. On 64 bit, the pool header structure size changes from `0x8` bytes to `0x10` bytes which makes exploitation more cumbersome; however, there are some good walkthroughs out there about how to accomplish this. For now, let's stick to x86. 

What do we need in order to exploit a use-after-free bug? Well, it seems like after doing this excercise we need to be able to do the following: 
+ allocate an object in the non-paged pool,
+ a mechansim that creates a reference to the object as a global variable, ie if our object is allocated at `0xFFFFFFFF`, there is some variable out there in the program that is storing that address for later use,
+ the ability to free the memory and not have the previously established reference NULLed out, ie when the chunk is freed the program author doesn't specify that the reference=NULL,
+ the ability to create "fake" objects that have the same size and **controllable** contents in the non-paged pool,
+ the ability to spray the non-paged pool and create perfectly sized holes so that our UAF and fake objects can be fitted in our created holes,
+ finally, the ability to **use** the no-longer valid reference to our freed chunk. 

## Allocating the UAF Object in the Pool
Let's take a look at the UAF object allocation routine in the driver in IDA. 
![](/assets/images/AWE/uaf2.PNG)

It may not be immediately clear what's going on without stepping through the routine in the debugger but we actually have very little control over what is taking place here. I've created a small skeleton exploit code and set a breakpoint towards the start of the routine. Here is our code at the moment:
```cpp
#include <iostream>
#include <Windows.h>

using namespace std;

#define DEVICE_NAME             "\\\\.\\HackSysExtremeVulnerableDriver"
#define ALLOCATE_UAF_IOCTL      0x222013
#define FREE_UAF_IOCTL          0x22201B
#define FAKE_OBJECT_IOCTL       0x22201F
#define USE_UAF_IOCTL           0x222017

HANDLE grab_handle() {

    HANDLE hFile = CreateFileA(DEVICE_NAME,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        cout << "[!] No handle to HackSysExtremeVulnerableDriver\n";
        exit(1);
    }

    cout << "[>] Grabbed handle to HackSysExtremeVulnerableDriver: " << hex
        << hFile << "\n";

    return hFile;
}

void create_UAF_object(HANDLE hFile) {

    BYTE input_buffer[] = "\x00";

    DWORD bytes_ret = 0x0;

    int result = DeviceIoControl(hFile,
        ALLOCATE_UAF_IOCTL,
        input_buffer,
        sizeof(input_buffer),
        NULL,
        0,
        &bytes_ret,
        NULL);
}


int main() {

    HANDLE hFile = grab_handle();

    create_UAF_object(hFile);

    return 0;
}
```

You can see from the IDA screenshot that after the call to `ExAllocatePoolWithTag`, `eax` is placed in `esi`, this is about where I've placed the breakpoint, we can then take the value in `esi` which should be a pointer to our allocation, and go see what the allocation will look like after the subsequent `memset` operation completes. We can see some static values as well, such as waht appears to be the size of the allocation (`0x58`), which we know from our last post is actually undersold by `0x8` since we have to account also for the pool header, so our real allocation size in the pool is `0x60` bytes. 

So we hit our breakpoint after `ExAllocatePoolWithTag` and then I just stepped through until the `memset` completed. 
![](/assets/images/AWE/uaf2.PNG)

Right after the `memset` completed, we look up our object in the pool and see that it's mostly been filled with `A` characters except for the first `DWORD` value has been left NULL. After stepping through the next two instructions:
![](/assets/images/AWE/uaf3.PNG)

We can see that the `DWORD` value has been filled and also that a null terminator has been added to the last byte of our allocation. This `DWORD` is the `UaFObjectCallback` which is a function pointer for a callback which gets used during a separate routine. 

And lastly in the screenshot we can see that move `esi`, which is the location of our allocation, into the global variable `g_UseAfterFreeObject`. This is important because this is what makes this code vulnerable as this same variable will not be nulled out when the object is freed. 

## Freeing the UAF Object
