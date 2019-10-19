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

## Let's Get to Coding
Anything that is very similar to our last post, I'll leave alone and only highlight significant changes. 
```asm
global_start


section .text
_start: 

xor ecx, ecx
mul ecx
mov eax, [fs:ecx + 0x30] ; PEB offset
mov eax, [eax + 0xc]     ; LDR offset
mov esi, [eax + 0x14]    ; InMemOrderModList
lodsd                    ; 2nd module
xchg eax, esi            ; 
lodsd                    ; 3rd module
mov ebx, [eax + 0x10]    ; kernel32 base address
mov edi, [ebx + 0x3c]    ; e_lfanew offset
add edi, ebx             ; offset + base
mov edi, [edi + 0x78]    ; export table offset
add edi, ebx             ; offset + base
mov esi, [edi + 0x20]    ; namestable offset
add esi, ebx             ; offset + base
xor ecx, ecx             
```

No big changes yet, this is identical to our last shellcode. We now have the address of `kernel32.dll` stored in ESI. 

```asm
Get_Function:
 
inc ecx                              ; increase ECX to keep track of our iterations
lodsd                                ; get name offset
add eax, ebx                         ; get function name
cmp dword [eax], 0x50746547          ; GetP
jnz Get_Function
cmp word [eax + 0xa], 0x73736572     ; ress
jnz Get_Function
```

Notic here we again, to save bytes, only compared the first 4 bytes `GetP` and the last 4 bytes `ress` of `GetProcAddress` to the string pointed to by EAX. Now that we have a match, our ECX register has kept track of how many iterations it took so we can move onto translating that into the actual memory address of the function. 

```asm
mov esi, [edi + 0x24]                ; ESI = Offset ordinals
add esi, ebx                         ; ESI = Ordinals table
mov cx, [esi + ecx * 2]              ; Number of function
dec ecx
mov esi, [edi + 0x1c]                ; Offset address table
add esi, ebx                         ; ESI = Address table
mov edi, [esi + ecx * 4]             ; EDi = Pointer(offset)
add edi, ebx                         ; EDi = GetProcAddress address
```
