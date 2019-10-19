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

Notice here we again, to save bytes, only compared the first 4 bytes `GetP` and the last 4 bytes `ress` of `GetProcAddress` to the string pointed to by EAX. Now that we have a match, our ECX register has kept track of how many iterations it took so we can move onto translating that into the actual memory address of the function. 

```asm
mov esi, [edi + 0x24]                ; ESI = Offset ordinals
add esi, ebx                         ; ESI = Ordinals table
mov cx, [esi + ecx * 2]              ; Number of function
dec ecx
mov esi, [edi + 0x1c]                ; Offset address table
add esi, ebx                         ; ESI = Address table
mov edi, [esi + ecx * 4]             ; EDI = Pointer(offset)
add edi, ebx                         ; EDI = GetProcAddress address
```

Nothing new here, I even copied @NytroRST's comments right out of his blog so that it's easier for you to follow along looking at his blog. We now have the memory address of `GetProcAddress` stored in EDI. 

```asm
; use GetProcAddress to find CreateProcessA
xor ecx, ecx
push 0x61614173
sub word [esp + 0x2], 0x6161
push 0x7365636f
push 0x72506574
push 0x61657243
push esp
push ebx
call edi
```

New code. Here we're using `GetProcAddress` to find the memory address of `CreateProcessA`. A cool technique that @NytroRST shows is to put non-4-byte strings on the stack with placeholder characters, such as `a` here, and then subtract them off the stack with a `sub` operation.

So, instead of pushing `CreateProcessA` which doesn't break up evenly into 4-byte chunks, we push `CreateProcessAaa`, which does. 

We push `0x61614173`, which is the last 4 bytes `sAaa`, and then subtract them off of the stack with the `sub` operation. We then push the rest of the string. 

Now that our string is on the stack, we push the pointer to it with `push esp` and then finally, we push the base address of `kernel32` onto the stack and call `GetProcAddress` with `call edi`. So we called the function with our two arguments on the stack that we discussed earlier: `HMODULE hModule` and `LPCSTR  lpProcName`. 

```asm
; EAX = CreateProcessA address
; ECX = kernel32 base address
; EDX = kernel32 base address
; EBX = kernel32 base address
; ESP = "CreateProcessA.."
; ESI = ???
; EDI = GetProcAddress address
```

During the shellcode writing process, I found it valuable to run the incomplete code in the debugger to keep track of register values and then place them in the shellcode after I used `GetProcAddress` since I was unfamiliar with it. Here we see several registers get filled with the `kernel32` address but the most important part is that EAX is filled with the address of `CreateProcessA` and EDI retained the address of `GetProcAddress` so that we can use it again later. 

```asm
xor ecx, ecx
xor edx, edx
mov cl, 0xff

zero_loop:
push edx
loop zero_loop

push 0x636c6163                      ; "calc"
mov ecx, esp

push ecx
push ecx
push edx
push edx
push edx
push edx
push edx
push edx
push ecx
push edx
call eax
```

Nothing new really, calling `CreateProcessA` and spawning a calculator. Time for a register value check. 

```asm
; EAX = 0x00000001
; ECX = some kernel32 address
; EDX = some stack Pointer
; EBX = kernel32 base
; EDI = GetProcAddress address
```

EAX is holding a non-zero return value from our `CreateProcessA` function call which indicates the function was successful. Our calculator has spawned. Now it's time to call `ExitProcess` and get out of here. 

```asm
add esp, 0x10                  ; clean the stack
push 0x61737365
sub dword [esp + 0x3], 0x61    ; essa - a    
push 0x636f7250                ; Proc
push 0x74697845                ; Exit
push esp
push ebx
call edi
```

We add `0x10` to ESP so that we get ourselves to a position on the stack that is not filled with junk from our last operation. We now have a blank canvas to work with on the stack and can start preparing it for our second `GetProcAddress` call. It's helpful to keep debugging your code as you go, so that you can see all the register conditions and stack in real time as you step through your program, I like to actually code inside of the debugger. Again, we use the `sub` operation trick since `ExitProcess` doesn't break up evenly into 4 byte chunks. Once we `call edi` here, we'll have the memory address of `ExitProcess` stored in EAX. 

```asm
xor ecx, ecx
push ecx
call eax
```

Pretty simple here, just calling `ExitProcess` and we only needed one parameter on the stack, our desired return value, which is `0` here. 

## Conclusion
We learned about using `GetProcAddress` when we have to make multiple function calls. What happens if the exported function we want isn't in `kernel32.dll`? Well, we'd have to use different techniques to first load those DLLs into memory, which we will do in subsequent posts. 

The calc shellcode now exits cleanly, is NULL free, and I think pretty short at 169 bytes. 

## Thanks
Thanks again to @NytroRST, couldn't have done any of this without his wonderful blog posts. Thanks to anyone who publishes educational content for free, it is a huge benefit to us, much appreciated. 

## Final Shellcode
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

Get_Function:
 
inc ecx                              ; Increment the ordinal
lodsd                                ; Get name offset
add eax, ebx                         ; Get function name
cmp dword [eax], 0x50746547          ; GetP
jnz Get_Function
cmp word [eax + 0xa], 0x73736572	   ; ress
jnz Get_Function
mov esi, [edi + 0x24]                ; ESI = Offset ordinals
add esi, ebx                         ; ESI = Ordinals table
mov cx, [esi + ecx * 2]              ; Number of function
dec ecx
mov esi, [edi + 0x1c]                ; Offset address table
add esi, ebx                         ; ESI = Address table
mov edi, [esi + ecx * 4]             ; EDi = Pointer(offset)
add edi, ebx                         ; EDi = GetProcAddress address

; use GetProcAddress to find CreateProcessA
xor ecx, ecx
push 0x61614173
sub word [esp + 0x2], 0x6161
push 0x7365636f
push 0x72506574
push 0x61657243
push esp
push ebx
call edi

; EAX = CreateProcessA address
; ECX = kernel32 base address
; EDX = kernel32 base address
; EBX = kernel32 base address
; ESP = "CreateProcessA.."
; ESI = ???
; EDI = GetProcAddress address

xor ecx, ecx
xor edx, edx
mov cl, 0xff

zero_loop:
push edx
loop zero_loop

push 0x636c6163                      ; "calc"
mov ecx, esp

push ecx
push ecx
push edx
push edx
push edx
push edx
push edx
push edx
push ecx
push edx
call eax

; EAX = 0x00000001
; ECX = some kernel32 address
; EDX = some stack Pointer
; EBX = kernel32 base
; EDI = GetProcAddress address

add esp, 0x10                   ; clean the stack
push 0x61737365
sub dword [esp + 0x3], 0x61    ; essa - a    
push 0x636f7250                ; Proc
push 0x74697845                ; Exit
push esp
push ebx
call edi

xor ecx, ecx
push ecx
call eax
```

