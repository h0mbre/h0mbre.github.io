---
layout: single
title: HEVD Exploits -- Windows 7 x86 Uninitialized Stack Variable
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

## Conclusion
