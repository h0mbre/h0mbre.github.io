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

Searching ExploitDB for 'SEH' and one of the first entries is the [Xitami Web Server 2.5 SEH Overflow](https://www.exploit-db.com/exploits/46797). By glancing at the exploit it looks like it utilizes an egghunter and also stores the final shellcode separately from the payload that crashes the application. This should be a great exercise for us to troubleshoot our way through. You can download the application from [here](https://imatix-legacy.github.io/xitami.com/)

## Fuzzing

In the last post we fuzzed another HTTP service and the `boofuzz` script only really fuzzed the first part of the request header. I wanted a way to dynamically create `boofuzz` scripts based on the HTTP requests actually sent to the web application, so I created a script to do just that. 

### Introducing Boo-Gen!

First, we want to grab a template HTTP request for the web application. Using Burpsuite, I just browsed to the address of the webserver and grabbed the `GET` request and saved it to a file called `get.txt`. 

![](/assets/images/CTP/xitamiHome.JPG)

![](/assets/images/CTP/xitamiBurp.JPG)


## Resources

+ [h0mbre's First SEH Overflow](https://h0mbre.github.io/SEH_Based_Exploit/#)
+ [Xitami Download](https://imatix-legacy.github.io/xitami.com/)
+ [Boo-Gen](https://github.com/h0mbre/CTP/tree/master/Boo-Gen)
+ [Offset.py](https://github.com/h0mbre/CTP/tree/master/Offset)
