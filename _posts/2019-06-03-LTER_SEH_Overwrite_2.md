---
layout: single
title: CTP/OSCE Prep -- 'LTER' SEH Overwrite Version 2.0!
date: 2019-6-03
classes: wide
header:
  teaser: /assets/images/CTP/immunity.jpg
tags:
  - buffer overflow
  - Windows
  - x86
  - shellcoding
  - exploit development
  - assembly
  - python
  - OSCE
  - CTP
  - SEH
--- 
![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## Introduction

This series of posts will focus on the concepts I'm learning/practicing in preparation for [CTP/OSCE](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/). In this series of posts, I plan on exploring:
+ fuzzing,
+ vanilla EIP overwrite,
+ SEH overwrite, and
+ egghunters.

Writing these entries will force me to become intimately familiar with these topics, and hopefully you can get something out of them as well! 

In this particular post we'll be using the skills we picked up last post to find our own way to exploit the 'LTER' command with an SEH overwrite.

If you have not already done so, please read some of the posts in the 'CTP/OSCE Prep' series as this post will be **light** on review! 

## Background 

This will be our third go at the 'LTER' command on Vulnserver. 
+ [The first time](https://h0mbre.github.io/LTER_SEH_Exploit/), I failed miserably to use the SEH overwrite, but I ended up discovering and EIP overwrite vulnerability with a smaller fuzzing payload.
+ [The second time](https://h0mbre.github.io/LTER_SEH_Success/#), I used @doylersec's approach to the SEH overwrite and worked through the exploit step-by-step for hours and was finally able to complete my own exploit modeled off of Doyler's.

Armed with the ability to use alphanumeric shellcode and a better understanding than the first time around, let's try to come up with our own unique take on the exploit and try to come up with something that's original to us.

## Getting Started



## Big Thanks

To everyone who has published free intro-level 32 bit exploit dev material, I'm super appreciative. Truly mean it. 

## Resources
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Corelan Mona Tutorial](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
