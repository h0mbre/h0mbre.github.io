---
layout: single
title: Baby's First Win32 Shellcode
date: 2019-10-17
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Shellcode
  - Windows
  - C++ 
  - CreateProcessA
  - Calc
---


## Win32 Shellcode
Earnestly starting my Windows exploitation journey and figured a good way to get familiar with some aspects of WinAPIs would be to create some pretty basic shellcode. We've spent the last couple of months just learning the basics of C/C++ so that background will help us here. MSDN does a pretty nice job of documenting the APIs and their constinuent parts. 

## Recommended Reading
These blogposts are awesome and both are part of a series. Both of them really spell out every single aspect creating dynamic shellcode that doesn't rely on hardcoded addresses. I won't spend much time in this blog post rehashing all of their wisdom, I beg you to read them, understand them, and go through them step by step in a debugger until you understand if you're at all interested in low-level programming on Windows/Shellcode, etc. 

+ [Introduction to Windows Shellcode Development -- Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/) by [@NytroRST](https://twitter.com/NytroRST)

+ [Windows SHellcoding x86 -- Hunting Kernel32.dll -- Part 1](https://0xdarkvortex.dev/index.php/2019/03/18/windows-shellcoding-x86-hunting-kernel32-dll-part-1/) by [@NinjaParanoid](https://twitter.com/NinjaParanoid)

We lean more on the former blog post, but in a subsequent blogpost we will be implementing the techiques discussed more in the latter. The techniques discussed in both blog posts are pretty similar with regards to finding the base address in memory of `kernel32.dll`.
