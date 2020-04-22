---
layout: single
title: HEVD Exploits -- Windows 7 x86 Non-Paged Pool Overflow
date: 2020-04-22
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
  - Pool Overflow
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
- To [@r0oki7](https://twitter.com/r0otki7) for their walkthrough: https://rootkits.xyz/blog/2017/11/kernel-pool-overflow/
- To [@FuzzySec](https://twitter.com/FuzzySec) for their walkthrough: http://www.fuzzysecurity.com/tutorials/expDev/20.html
- and finally to [@steventseeley](https://twitter.com/steventseeley) for his walkthrough of his exploit of a Jungo driver here: https://srcincite.io/blog/2017/09/06/sharks-in-the-pool-mixed-object-exploitation-in-the-windows-kernel-pool.html

This exploit required a lot of insight into the non-paged pool internals of Windows 7. These walkthroughs/blogs were extremely well written and made everything very logical and clear. I really appreciate the authors' help! Again, I'm just recreating other people's exploits in this series trying to learn, not inventing new ways to exploit pool overflows for 32 bit Windows 7. The exploit also required allocating the NULL page, which isn't possible on x64 so this will be a 32 bit exploit only. 

## Reversing Relevant Function
The bug for this driver routine is really similar to some of the stack based buffer overflow vulnerabilities we've already done like the stack overflow and the integer overflow. We get a user buffer and send it to the routine which will allocate a kernel buffer and copy our user buffer into the kernel buffer. The only difference here is the type of memory used. Instead of the stack, this [memory](https://docs.microsoft.com/en-us/windows/win32/memory/memory-pools) is allocated in the non-paged pool which are pool chunks that are guaranteed to be in physical memory (RAM) at all times and cannot be paged out. This stands in contrast to paged pool which is allowed to be "paged out" when there is no more RAM capacity to a secondary storage medium. 

The APIs that are relevant here in this routine are `ExAllocatePoolWithTag` and `ExFreePoolWithTag`. This [API](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag) prototype looks like this:
```cpp
PVOID ExAllocatePoolWithTag(
  __drv_strictTypeMatch(__drv_typeExpr)POOL_TYPE PoolType,
  SIZE_T                                         NumberOfBytes,
  ULONG                                          Tag
);
```

In our routine all of these parameters are hardcoded for us. `PoolType` is set to `NonPagedPool`, `NumberOfBytes` is set to `0x1F8`, and `Tag` is set to `0x6B636148` ('Hack'). This by itself is fine and there is no vulnerability obviously; however, the driver routine uses `memcpy` to transfer data from the user buffer to this newly allocated non-paged pool kernel buffer and uses the size of the **user buffer** as the size argument. (This precisely the bug in the Jungo driver that @steventseeley discovered via fuzzing.) If the size of our user buffer is larger than the kernel buffer, we will overwrite some data in the adjacent non-paged pool.  Here is a screenshot of the function in IDA Free 7.0. 

![](/assets/images/AWE/poolover1.PNG)

Nothing too complicated reversing wise, we can even see that right after our pool buffer is allocated, it is de-allocated with `ExFreePoolWithTag`.

If we call the function with the following skeleton code, we will see in WinDBG that everything works as normal and we can start trying to understand how the pool chunks are structured. 
```cpp
#include <iostream>
#include <Windows.h>

using namespace std;

#define DEVICE_NAME         "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL               0x22200B


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

void send_payload(HANDLE hFile) {

    ULONG payload_len = 0x1F8;

    LPVOID input_buff = VirtualAlloc(NULL,
        payload_len + 0x1,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    memset(input_buff, '\x42', payload_len);

    cout << "[>] Sending buffer size of: " << dec << payload_len << "\n";

    DWORD bytes_ret = 0;

    int result = DeviceIoControl(hFile,
        0x22200F,
        input_buff,
        payload_len,
        NULL,
        0,
        &bytes_ret,
        NULL);

    if (!result) {

        cout << "[!] DeviceIoControl failed!\n";

    }
}

int main() {

    HANDLE hFile = grab_handle();

    send_payload(hFile);

    return 0;
}
```

I set a breakpoint at offset 0x4D64 with this command in WinDBG: `bp !HEVD+4D64` which is right after the `memcpy` operation and we see that our pool buffer has been filled with our `\x42` characters. At this point a pointer to the allocated kernel buffer is still in `eax` so we can go to that location with the `!pool` command which will start at the beginning of that page of memory and display certain aspects of the memory allocated there.

![](/assets/images/AWE/poolover2.PNG)







