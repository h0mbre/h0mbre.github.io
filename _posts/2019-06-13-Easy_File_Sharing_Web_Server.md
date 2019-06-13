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

The first thing I noticed was that the script apparently creates a list of HTTP methods for `boofuzz` to craft packets from and also fuzzes the `s_delim` entities `'space-1'` and `'space-2'`. It also fuzzes the `s_string` entities `'Request-URI'` and `'HTTP-Version'`. `boofuzz` does not fuzz `s_static` entities. 

As you can probably gather, this isn't a super in-depth fuzzing script but it's a great start. It's going to test several HTTP methods and it's going to fuzz about 4 values. Fields such as User Agent or SESSIONID will not be fuzzed, but we can save that for another time.

After a round of fuzzing, the application crashes relatively closely and as you can see from the screenshot, we notice EAX has been overwritten with `C` values. 

![](/assets/images/CTP/efscrash1.JPG)


## Resources

+ 
