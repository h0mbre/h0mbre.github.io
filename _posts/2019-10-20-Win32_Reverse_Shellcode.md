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
