---
layout: single
title: CTP/OSCE Prep -- Xitami Webserver 2.5 SEH Overflow With Egghunter 
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

Since I've just about finished all of the Vulnserver exploits and have gone through most of the CTP material, I figured it's time to start getting some experience recreating real world exploits from scratch. I searched for 'SEH' on ExploitDB and settled on the [Easy File Sharing Web Server 7.2](https://www.exploit-db.com/exploits/39008) exploit. I picked this exploit in particular because up to this point I have not done much exploit developement with webservers, most of my experience has come from Vulnserver.  

## Fuzzing



## Resources

+ [Exploit DB Entry for Easy File Sharing Webserver](https://www.exploit-db.com/exploits/39008)
+ [EFS Download](http://www.sharing-file.com/)
+ [HTTP Exploit Skeleton](https://github.com/HanseSecure/ExploitDev/blob/master/poc/http.py)
+ [Boofuzz HTTP Template](https://stackoverflow.com/questions/45355344/http-fuzzing-with-boofuzz)
