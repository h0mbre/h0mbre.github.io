---
layout: single
title: HEVD Exploits -- Windows 7 x86 Integer Overflow
date: 2020-04-20
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
  - Integer Overflow
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
Thanks to @tekwizz123, I used his method of setting up the exploit buffer for the most part as the Windows macros I was using weren't working (obviously user error.)

## Integer Overflow
This was a really interesting bug to me. Generically, the bug is when you have some arithmetic in your code that allows for unintended behavior. The bug in question here involved incrementing a `DWORD` value that was set `0xFFFFFFFF` which overflows the integer size and wraps the value around back to `0x00000000`. If you add `0x4` to `0xFFFFFFFF`, you get `0x100000003`. However, this value is now over 8 bytes in length, so we lose the leading `1` and we're back down to `0x00000003`. Here is a small demo program:
```cpp
#include <iostream>
#include <Windows.h>

int main() {

	DWORD var1 = 0xFFFFFFFF;
	DWORD var2 = var1 + 0x4;

	std::cout << ">> Variable One is: " << std::hex << var1 << "\n";
	std::cout << ">> Variable Two is: " << std::hex << var2 << "\n";
}
```

Here is the output:
```
>> Variable One is: ffffffff
>> Variable Two is: 3
```

I actually learned about this concept from Gynvael Coldwind's [stream on fuzzing](https://www.youtube.com/watch?v=BrDujogxYSk). I also found the bug in my own code for an exploit on a real vulnerability I will hopefully be doing a write-up for soon (when the CVE gets published.) Now that we know how the bug occurs, let's go find the bug in the driver in IDA and figure out how we can take advantage. 

## Reversing the Function
![](/assets/images/AWE/IntOverflowFunc.PNG)

With the benefit of the comments I made in IDA, we can kind of see how this works. I've annotated where everything is after stepping through in WinDBG. 

The first thing we notice here is that `ebx` gets loaded with the length of our input buffer in `DeviceIoControl` when we do this operation here: `move ebx, [ebp+Size]`. This is kind of obvious, but I hadn't really given it much thought before. We allocate an input buffer in our code, usually its a character or byte array, and then we usually satisfy the `DWORD nInBufferSize` parameter by doing something like `sizeof(input_buffer)` because we actually want it to be accurate. Later, we might actually lie a little bit here. 

Now that `ebx` is the length of our input buffer, we see that it gets `+4` added to it and then loaded into to `eax`. If we had an input buffer of `0x7FC`, adding `0x4` to it would make it `0x800`. A really important thing to note here is that we've essentially created a new length variable in `eax` and kept our old one in `ebx` intact. In this case, `eax` would be `0x800` and `ebx` would still hold `0x7FC`. 

Next, `eax` is compared to `esi` which we can see holds `0x800`. If the `eax` is equal to or more than `0x800`, we can see that take the red path down to the `Invalid UserBuffer Size` debug message. We don't want that. We need to satisfy this `jbe` condition. 

If we satisfy the `jbe` condition, we branch down to `loc_149A5`. We put our buffer length from `ebx` into `eax` and then we effectively divide it by 4 since we do a bit shift right of 2. We compare this to quotient to `edi` which was zeroed out previously and has remained up until now unchanged. If length/4 quotient is the same or more than the counter, we move to `loc_149F1` where we will end up exiting the function soon after. Right now, since our length is more than `edi`, we'll jump to `mov eax, [ebp+8]`. 

This series of operations is actually the interesting part. `eax` is given a pointer to our input buffer and we compare the value there with `0BAD0B0B0`. If they are the same value, we move towards exiting the function. So, so far we have identified two conditions where we'll exit the function: if `edi` is ever equal to or more than the length of our input buffer divided by 4 ***OR*** if the 4 byte value located at `[ebp+8]` is equal to `0BAD0B0B0`.

Let's move on to the final puzzle piece. `mov [ebp+edi*4+KernelBuffer], eax` is kind of convoluted looking but what it's doing is placing the 4 byte value in `eax` into the kernel buffer at index `edi * 0x4`. Right now, `edi` is 0, so it's placing the 4 byte value right at the beginning of the kernel buffer. After this, the `dword ptr` value at `ebp+8` is incremented by `0x4`. This is interesting because we already know that `ebp+0x8` is where the pointer is to our input buffer. So now that we've placed the first four bytes from our input buffer into the kernel buffer, we move now to the next 4 bytes. We see also that `edi` incremented and we now understand what is taking place. 

As long as:

1. the length of our buffer + 4 is `< 0x800`,
2. the `Counter` variable (`edi`) is `<` the length of our buffer divided by 4, 
3. and the 4 byte value in `eax` is not `0BAD0B0B0`,

we will copy 4 bytes of our input buffer into the kernel buffer and then move onto the next 4 bytes in the input buffer to test criteria 2 and 3 again. 

There can't really be a problem with copying bytes from the user buffer into the kernel buffer unless somehow the copying exceeds the space allocated in the kernel buffer. If that occurs, we'll begin overwriting adjacent memory with our user buffer. How can we fool this length + `0x4` check?

## Manipulating `DWORD nInBufferSize`
First we'll send a vanilla payload to test our theories up to this point. Let's start by sending a buffer full of all `\x41` chars and it will be a length of `0x750` (null-terminated). We'll use the `sizeof() - 1` method to form our `nInBufferSize` parameter and account for the null terminator as well so that everything is accurate and consistent. Our code will look like this at this point:
```cpp
#include <iostream>
#include <string>
#include <iomanip>

#include <Windows.h>

using namespace std;

#define DEVICE_NAME         "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL               0x222027

HANDLE get_handle() {

    HANDLE hFile = CreateFileA(DEVICE_NAME,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        cout << "[!] No handle to HackSysExtremeVulnerableDriver.\n";
        exit(1);
    }

    cout << "[>] Handle to HackSysExtremeVulnerableDriver: " << hex << hFile
        << "\n";

    return hFile;
}

void send_payload(HANDLE hFile) {

    

    BYTE input_buff[0x751] = { 0 };

    // 'A' * 1871
    memset(
        input_buff,
        '\x41',
        0x750);

    cout << "[>] Sending buffer of size: " << sizeof(input_buff) - 1  << "\n";

    DWORD bytes_ret = 0x0;

    int result = DeviceIoControl(hFile,
        IOCTL,
        &input_buff,
        sizeof(input_buff) - 1,
        NULL,
        0,
        &bytes_ret,
        NULL);

    if (!result) {
        cout << "[!] Payload failed.\n";
    }
}

int main()
{
    HANDLE hFile = get_handle();

    send_payload(hFile);
}
```

What are our predictions for this code? What conditions will we hit? The criteria for copying bytes from user buffer to kernel buffer was: 
1. the length of our buffer + 4 is `< 0x800`,
2. the `Counter` variable (`edi`) is `<` the length of our buffer divided by 4, 
3. and the 4 byte value in `eax` is not `0BAD0B0B0`

We should pass the first check since our buffer is indeed small enough. This second check will eventually make us exit the function since our length divided by 4, will eventually be caught by the `Counter` as it increments every 4 byte copy. We don't have to worry about the third check as we don't have this string in our payload. Let's send it and step through it in WinDBG. 

![](/assets/images/AWE/intover1.PNG)

This picture helps us a lot. I've set a breakpoint on the comparison between the length of our buffer + 4 and `0x800`. As you can see, `eax` holds `0x754` which is what we would expect since we sent a `0x750` byte buffer. 

In the bottom right, we our user buffer was allocated at `0x0012f184`. Let's set a [break on access](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ba--break-on-access-) at `0x0012f8d0` since that is `0x74c` away from where we are now, which is `0x4` short of `0x750`. If this 4 byte address is accessed for a read-operation we should hit our breakpoint. This will occur when the program goes to copy the 4 byte value here to the kernel buffer. 

The syntax is `ba r1 0x0012f8d0` which means "break on access if there is a read of at least 1 byte at that address."

We resume from here, we hit our breakpoint. 

![](/assets/images/AWE/intover2.PNG)


## Conclusion
