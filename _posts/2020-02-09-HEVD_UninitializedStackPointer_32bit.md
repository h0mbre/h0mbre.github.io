---
layout: single
title: HEVD Exploits -- Windows 7 x86 Uninitialized Stack Variable
date: 2020-02-09
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Exploit Dev
  - Drivers
  - Windows
  - x86
  - Shellcoding
  - Kernel Exploitation
  - Uninitialized Stack Variable
---

## Introduction
Continuing on with the Windows exploit journey, it's time to start exploiting kernel-mode drivers and learning about writing exploits for ring 0. As I did with my OSCE prep, I'm mainly blogging my progress as a way for me to reinforce concepts and keep meticulous notes I can reference later on. I can't tell you how many times I've used my own blog as a reference for something I learned 3 months ago and had totally forgotten. 

This series will be me attempting to run through every exploit on the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). **I will be using HEVD 2.0**. I can't even begin to explain how amazing a training tool like this is for those of us just starting out. There are a ton of good blog posts out there walking through various HEVD exploits. I recommend you read them all! I referenced them heavily as I tried to complete these exploits. Almost nothing I do or say in this blog will be new or my own thoughts/ideas/techniques. There were instances where I diverged from any strategies I saw employed in the blogposts out of necessity or me trying to do my own thing to learn more.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits. 

I used the following blogs as references:
+ All of the previous referenced blog posts in the series (obviously I'm reusing code I learned from them every exploit),

## Goal