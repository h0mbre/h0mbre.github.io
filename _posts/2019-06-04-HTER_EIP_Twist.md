---
layout: single
title: CTP/OSCE Prep -- 'HTER' EIP Overwrite with a Twist
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
Then I saw **this** in EIP. 

![](/assets/images/CTP/wtfEIP.JPG)

## EIP, wyd? 

So with 8 `A` values in `EIP` something is not normal here. Two possibilities come to mind: 
1. Our 32 bit registers can now hold 8 bytes via *magic*
2. The characters are not being interpreted/stored as ASCII, but maybe Hex? 

I'm going with option two here and testing it to see if we're right. (*Psst. I actually didn't even notice the 8 `A` until I found the offset and stuffed it with 8 `B`, but let's pretend I'm ontop of this stuff.*)

### Finding an Offset

Since we are guessing these chars are being interpreted as raw hex and not ASCII, mona is out for pattern create and pattern offset. What I did was cut my 3000 char buffer in half and made it 1500 `A` and 1500 `B` and repeated with similar techniques until I found the correct offset and was able to have my payload include only 8 `B` and all 8 ended up in `EIP`. 

![](/assets/images/CTP/8beip.PNG)



## Resources

+ [Do Buffer Overflow Good](https://github.com/justinsteven/dostackbufferoverflowgood)
+ [Finding Bad Characters](https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/)
+ [Intro to Boofuzz](https://zeroaptitude.com/zerodetail/fuzzing-with-boofuzz/)
+ [Vulnserver EIP Overwrite](https://captmeelo.com/exploitdev/osceprep/2018/06/27/vulnserver-trun.html)
+ [Vulnserver LTER EIP Overwrite](https://www.doyler.net/security-not-included/vulnserver-lter-eip-overwrite)
+ [Mona Guide](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
+ [Immunity Debugger Basics](https://hsploit.com/immunity-debugger-basics/)
+ [Wallpaper](https://imgur.com/0S9DVnQ)
