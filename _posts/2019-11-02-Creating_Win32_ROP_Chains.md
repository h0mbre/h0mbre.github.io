---
layout: single
title: Creating Win32 ROP Chains 
date: 2019-11-02
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Shellcode
  - Windows
  - Assembly
  - Return Oriented Programming 
  - ROP
  - Exploit Development
  - DEP Bypass
---

## Introduction
Continuing with the Windows exploit development our next stop is learning how to craft ROP chains. In the context of this blogpost we will be using them to disable DEP and execute shellcode on the stack; however, ROP chains are extremely versatile and in different contexts can be very powerful. Obviously stack based overflows aren't a very common bug class these days compared to 10 years ago, but this will allow us to use concepts we're familiar with (stack overflows) to learn concepts that are new to us (ROP chains). 

## ROP Chains
ROP stands for Return Oriented Programming. Essentially what we're doing is placing pointers to instructions on the stack, having execution follow those pointers to execute the instructions at that location and then execution returns to the stack to the next pointer. 

The reason this behavior is desirable is because when Data Execution Prevention (DEP) is enabled, we are typically unable to execute code in any section of memory that doesn't explicitly contain executable instructions. This means our traditional stack based overflow attacks won't work as we cannot execute shellcode on the stack. 

This is where the power of ROP comes into play. We uses tiny sections of existing code in the target program that are punctuated in sequence by a `RETN` instruction and piece them together to make a function call which disables DEP. We can then run our shellcode on the stack as we're used to. 

## Required Reading
Corelan has essentially written a manifesto on DEP and Win32 ROP chains [here](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/). Nothing I say or do in this blog is new or groundbreaking, I'm simply recapitulating the ROP learning process for beginners like myself interested in taking their Windows game further and documenting my work for my own reference. 

FuzzySec also has a phenomenal post [here](https://www.fuzzysecurity.com/tutorials/expDev/7.html) as part of their Tutorials series which also does a great job of walking through the reasoning and logic behind ROP chains.

You need to read and understand these blog posts very well in order to keep up. I will do my best to step through the process with the reader; however, it's always best to consult multiple sources and Corelan and Fuzzy are much more experienced and knowledgeable than I am. 

