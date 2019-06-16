---
layout: single
title: CTP/OSCE Prep -- Xitami Webserver 2.5 SEH Overflow With Egghunter 
date: 2019-6-15
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
  - ExploitDB
  - egghunter
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

Searching ExploitDB for 'SEH' and one of the first entries is the [Xitami Web Server 2.5 SEH Overflow](https://www.exploit-db.com/exploits/46797). By glancing at the exploit it looks like it utilizes an egghunter and also stores the final shellcode separately from the payload that crashes the application. This should be a great exercise for us to troubleshoot our way through. You can download the application from [here](https://imatix-legacy.github.io/xitami.com/).

## Fuzzing

In the last post we fuzzed another HTTP service and the `boofuzz` script only really fuzzed the first part of the request header. I wanted a way to dynamically create `boofuzz` scripts based on the HTTP requests actually sent to the web application, so I created a script to do just that. 

### Introducing Boo-Gen!

[Boo-Gen is a simple Python script](https://github.com/h0mbre/CTP/tree/master/Boo-Gen) which uses an example HTTP request (right now just the headers) to generate a `boofuzz` script. It should function dynamically and work with any headers that follow a `Parameter: Value` paradigm. All you need is an example `.txt` file with your HTTP request.

First, we want to grab a template HTTP request for the web application. Using Burpsuite, I just browsed to the address of the webserver and grabbed the `GET` request and saved it to a file called `get.txt`. 

![](/assets/images/CTP/xitamiHome.JPG)

![](/assets/images/CTP/xitamiBurp.JPG)

Right-clicking anywhere in the `GET` request and selecting 'Copy to file' within Burp allows us to save the request a `.txt` file. Now we just need to feed this request to Boo-Gen and let it do its thing. We will not specify an output file name with the `-f, --filename` flag and will instead let it default to `http.py`. 
```terminal
root@kali:~/OSCE/ # python boo-gen.py get.txt
```

We can now open the newly created `http.py` file and inspect its contents. 
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
        s_group("Method", ['GET', 'POST'])
        s_delim(" ", name='space-1', fuzzable = False)
        s_string("/index.html", name='Request-URI', fuzzable = False)
        s_delim(" ", name='space-2', fuzzable = False)
        s_string("HTTP/1.1", name='HTTP-Version', fuzzable = False)
	s_delim("\r\n", name='return-1', fuzzable = False)
	s_string("Host:", name="Host", fuzzable = False)
	s_delim(" ", name="space-3", fuzzable = False)
	s_string("192.168.1.201", name="Host-Value", fuzzable = False)
	s_delim("\r\n", name="return-2", fuzzable = False)
	s_string("User-Agent:", name="User-Agent", fuzzable = False)
	s_delim(" ", name="space-4", fuzzable = False)
	s_string("Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0", name="User-Agent-Value", fuzzable = False)
	s_delim("\r\n", name="return-3", fuzzable = False)
	s_string("Accept:", name="Accept", fuzzable = False)
	s_delim(" ", name="space-5", fuzzable = False)
	s_string("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", name="Accept-Value", fuzzable = False)
	s_delim("\r\n", name="return-4", fuzzable = False)
	s_string("Accept-Language:", name="Accept-Language", fuzzable = False)
	s_delim(" ", name="space-6", fuzzable = False)
	s_string("en-US,en;q=0.5", name="Accept-Language-Value", fuzzable = False)
	s_delim("\r\n", name="return-5", fuzzable = False)
	s_string("Accept-Encoding:", name="Accept-Encoding", fuzzable = False)
	s_delim(" ", name="space-7", fuzzable = False)
	s_string("gzip, deflate", name="Accept-Encoding-Value", fuzzable = False)
	s_delim("\r\n", name="return-6", fuzzable = False)
	s_string("Connection:", name="Connection", fuzzable = False)
	s_delim(" ", name="space-8", fuzzable = False)
	s_string("close", name="Connection-Value", fuzzable = False)
	s_delim("\r\n", name="return-7", fuzzable = False)
	s_string("Upgrade-Insecure-Requests:", name="Upgrade-Insecure-Requests", fuzzable = False)
	s_delim(" ", name="space-9", fuzzable = False)
	s_string("1", name="Upgrade-Insecure-Requests-Value", fuzzable = False)
	s_delim("\r\n", name="return-8", fuzzable = False)
	s_string("If-Modified-Since:", name="If-Modified-Since", fuzzable = False)
	s_delim(" ", name="space-10", fuzzable = False)
	s_string("Sat, 15 Jun 2019 01:36:09 GMT", name="If-Modified-Since-Value", fuzzable = False)
	s_delim("\r\n", name="return-9", fuzzable = False)
	s_string("Cache-Control:", name="Cache-Control", fuzzable = False)
	s_delim(" ", name="space-11", fuzzable = False)
	s_string("max-age=0", name="Cache-Control-Value", fuzzable = False)
	s_delim("\r\n", name="return-10", fuzzable = False)
        s_static("\r\n", name="Request-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))

    session.fuzz()


if __name__ == "__main__":
    main()
```

Comparing this output file to our `get.txt` file and everything looks the way it should! Notice that everything right now is set to `fuzzable = False` which means, as is, our `boofuzz` script will only send requests that match our `get.txt` file. We will have manually enable fuzzing for each parameter we want to fuzz. This is just a personal taste, if you don't like this approach, feel free to just delete instances of `fuzzable = False` in `boo-gen.py`. 

### Getting Fuzzy 

After spending quite a long time fuzzing the application, I was unable to get it to crash. Eventually I had to peek at the ExploitDB PoC script and determine how they were able to make the application crash. It turns out the `If-Modified-Since` parameter in our `boofuzz` script **is** vulnerable; however, it actually requires the parameter value to be prepended by a day and a space. So it needs to look like this: `If-Modified-Since: Wed, <fuzzing-payload>`. 

So we need to alter our `boofuzz` script slightly, in particular these few lines:
```python
s_string("If-Modified-Since: Sat,", name="If-Modified-Since", fuzzable = False)
s_delim(" ", name="space-10", fuzzable = False)
s_string("15 Jun 2019 01:36:09 GMT", name="If-Modified-Since-Value")
```

`"If-Modified-Since"` now has the day included along with a comma. This entity will not be fuzzed as it's set to `fuzzable = False`. The `"If-Modified-Since-Value"` entity has been shortened and we have deleted the fuzzable declaration so now it will be fuzzed. 

Sending this to our webserver nets us our crash!


## Resources

+ [h0mbre's First SEH Overflow](https://h0mbre.github.io/SEH_Based_Exploit/#)
+ [Xitami Download](https://imatix-legacy.github.io/xitami.com/)
+ [Boo-Gen](https://github.com/h0mbre/CTP/tree/master/Boo-Gen)
+ [Offset.py](https://github.com/h0mbre/CTP/tree/master/Offset)
