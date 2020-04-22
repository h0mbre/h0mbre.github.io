---
layout: single
title: HEVD Exploits -- Windows 7 x86 Non-Paged Pool Overflow
date: 2020-04-22
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
  - Pool Overflow
---

## Introduction
Continuing on with my goal to develop exploits for the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). **I will be using HEVD 2.0**. There are a ton of good blog posts out there walking through various HEVD exploits. I recommend you read them all! I referenced them heavily as I tried to complete these exploits. Almost nothing I do or say in this blog will be new or my own thoughts/ideas/techniques. There were instances where I diverged from any strategies I saw employed in the blogposts out of necessity or me trying to do my own thing to learn more.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits.

## Thanks
- To [@r0oki7](https://twitter.com/r0otki7) for their walkthrough: https://rootkits.xyz/blog/2017/11/kernel-pool-overflow/
- To [@FuzzySec](https://twitter.com/FuzzySec) for their walkthrough: http://www.fuzzysecurity.com/tutorials/expDev/20.html
- and finally to [@steventseeley](https://twitter.com/steventseeley) for his walkthrough of his exploit of a Jungo driver here: https://srcincite.io/blog/2017/09/06/sharks-in-the-pool-mixed-object-exploitation-in-the-windows-kernel-pool.html

This exploit required a lot of insight into the non-paged pool internals of Windows 7. These walkthroughs/blogs were extremely well written and made everything very logical and clear. I really appreciate the authors' help! Again, I'm just recreating other people's exploits in this series trying to learn, not inventing new ways to exploit pool overflows for 32 bit Windows 7. The exploit also required allocating the NULL page, which isn't possible on x64 so this will be a 32 bit exploit only. 



![](/assets/images/AWE/intover6.PNG)
