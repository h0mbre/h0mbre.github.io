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

We see that it takes two arguments, `HMODULE` is simply the base address of a of a DLL and `LPCSTR` is a pointer to a string value with the desired function name we want to find the address of.

The function returns the address of the desired exported function and stores it in EAX. 

So we can find the address of `GetProcAddress` the same way we did last time for `CreateProcessA` and then repeatedly call on `GetProcAddress` to find subsequent function addresses for us. This comes in very handy when you have use more than one function. Last time we really only used `CreateProcessA` so we didn't need this flexibility. 

### ExitProcess
We will end up using the function `ExitProcess` to exit our shellcode gracefully. It's a relatively simple function and really only requires an exit code according to the [MSDN documentation](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess): 
```c++
void ExitProcess(
  UINT uExitCode
);
```

### New Shellcode Outline
Roughly, our shellcode will do the following:
+ Find base address of `kernel32.dll`
+ Comb through `kernel32.dll` for the address of the exported `GetProcAddress` function
+ Use `GetProcAddress` to find the address of and call `CreateProcessA`
+ Use `CreateProcessA` to spawn a calculator
+ Use `GetProcAddress` to find the address of and call `ExitProcess` which will quit our program cleanly. 

Sounds simple? Let's get to it!
