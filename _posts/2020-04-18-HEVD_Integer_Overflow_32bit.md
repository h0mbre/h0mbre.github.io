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
1- the length of our buffer + 4 is `< 0x800`, 
2- the `Counter` variable (`edi`) is `<` the length of our buffer divided by 4, 
3- and the 4 byte value in `eax` is not `0BAD0B0B0`,

we will copy 4 bytes of our input buffer into the kernel buffer and then move onto the next 4 bytes in the input buffer to test criteria 2 and 3 again. 

## Conclusion
