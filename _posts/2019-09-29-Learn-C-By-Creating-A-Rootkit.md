---
layout: single
title: Making a Simple Userland Rootkit for Linux 
date: 2019-9-29
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Linux
  - Socket Programming
  - C
  - Rootkits
  - LD_PRELOAD
  - Jynx Rootkit
--- 

## Background Information
This post is my solution for the last assignment in my [Learning-C](https://github.com/h0mbre/Learning-C) repository. I thought a good way to cap off a repo designed to introduce people to very basic C programming would be to take those very basic techinques and make a simple yet powerful security related tool, namely a malicious shared library rootkit.

I came across LD_PRELOAD rootkits while watching [a talk by @r00tkillah](https://www.youtube.com/watch?v=wyRRbow4-bc&feature=youtu.be) in 2016 about his initrd rootkit. He talks about historical approaches to Linux rootkits and the LD_PRELOAD approach gets some good coverage. Since it was described in the talk as a userland approach, I started reading about them and quickly discovered a few well-known implementations, namely the [Jynx Rootkit](https://github.com/chokepoint/Jynx2). Jynx has a lot of articles discussing its features and how to detect it. It was fairly robust, checking in at around 1,500 lines of code in the main file and hooking ~20 syscalls. 

My goal for this assignment since we had just learned how to hook syscalls in the previous assignment, was to create a userland rootkit which:
- provided a backdoor/command-shell opportunity,
- hid malicious network connections from `netstat` and `lsof`, and
- hid malicious files. 

**To be clear:** I'm fully aware this isn't an elite, APT-level rootkit ready to use for Red Teams world-wide. These techniques have been analyzed and discussed for around 7 years now. **BUT** it is sort of a niche subject and something I don't think many people have come across. I would also like to just point people towards blogs and posts that detail the technical details at play here instead of expounding on those details myself, as I am not an expert. 

All of this is possible with very simple C. (hacky, bad C at that!) 
