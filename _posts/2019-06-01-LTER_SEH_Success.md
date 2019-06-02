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

One way to overcome this limitation is to 'sub encode' your shellcode. As VelloSec explains in [CARVING SHELLCODE USING RESTRICTIVE CHARACTER SETS](http://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/), the manual process for sub encoding your payloads can be very tedious. I really recommend you read the VelloSec blog post. I probably had to read it through 4 times today. 


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

As you can see, we ended up back at our `F7` without ever using it! That fundamental concept will be what we use throughout this exploit. 

### Automating Encoding 
At a high-level what we're going to accomplish with sub encoding and how we're going to use it in this exploit is: 
1. We're going to use `AND` operations to zero out the `EAX` register,
2. We're going to manipulate the `EAX` register with `SUB` and `ADD` instructions so that it eventually holds the value of our intended 4 byte payload,
3. We're going to push that value onto the stack so that `ESP` is pointing to it. 

As VelloSec put it lightly, manual encoding each 4 byte string can be tedious (especially if at some point you have to encode an entire reverse shell payload). Luckily, @ihack4falafel (Hashim Jawad) has created an amazing encoder called [Slink](https://github.com/ihack4falafel/Slink) for us to use. His encoder uses more `ADD` instructions but abuses the same wrap around concept. 

Let's show an example of how to use the tool with the test payload: `\xfe\xcf\xff\xe3`

![](/assets/images/CTP/test1.gif)


## Resources
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Corelan Mona Tutorial](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
