---
layout: single
title: Baby's First Win32 Shellcode Part 2
date: 2019-10-19
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Shellcode
  - Windows
  - C++ 
  - Assembly
  - CreateProcessA
  - Calc
  - GetProcAddress
  - ExitProcess  
---

## Overview
Picking up where we left off in the [last post](https://h0mbre.github.io/Babys-First-Shellcode/), we're going to add an exit routine to our shellcode so that it exits gracefully and does not crash. We will be copying a lot of code and concepts from [@NytroRST's Blogpost](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/), so make sure you have read through it and understand it well. 

## New Concepts
Everything in our code will basically remain unchaged, we'll simply be adding intermediate steps and also an exit routine at the end. This will obviously change how we're using the registers to a degree as well. 

### GetProcAddress
Instead of combing through `kernel32.dll` for `CreateProcessA`, this time we're going to find the address of the function `GetProcAddress`. According to the [MSDN documentation](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress), the syntax looks like this:
```c++
FARPROC GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName
);
```
