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

**To be clear:** I'm fully aware this isn't a robust, red-team-ready rootkit ready to use for engagements. These techniques have been analyzed and discussed for around 7 years now. **BUT** it is sort of a niche subject and something I don't think many people have come across. I would also like to just point people towards blogs and posts that detail the technical details at play here instead of expounding on those details myself, as I am not an expert. 

All of this is possible with very simple C. (hacky, bad C at that!)

## Shared Libraries and LD_PRELOAD

A lot has been written on the topic of Shared Libraries so I won't spend much time here explaining them (we even touched on them in the last post). Shared or dynamic libraries define functions that the dynamic linker links to other programs during their run time. A common example is [libc](http://man7.org/linux/man-pages/man7/libc.7.html). This reduces the amount of code you need in a program executable because it shares function definitions with a library. 

`LD_PRELOAD` is a configurable environment variable that allows users to specify a shared library to be loaded into memory for programs before other shared libraries. Just a quick example, if we check the shared libraries used by `/bin/ls` on a standard x86 Kali box, we get:
```terminal_session
tokyo:~/ # ldd /bin/ls                                             
	linux-gate.so.1 (0xb7fcf000)
	libselinux.so.1 => /lib/i386-linux-gnu/libselinux.so.1 (0xb7f57000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7d79000)
	libpcre.so.3 => /lib/i386-linux-gnu/libpcre.so.3 (0xb7d00000)
	libdl.so.2 => /lib/i386-linux-gnu/libdl.so.2 (0xb7cfa000)
	/lib/ld-linux.so.2 (0xb7fd1000)
	libpthread.so.0 => /lib/i386-linux-gnu/libpthread.so.0 (0xb7cd9000)
```

So we see a number of shared library dependencies for `/bin/ls`. If we set the environment variable for `LD_PRELOAD` to a notional shared library we can actually change what shared library dependencies that binary has. Furthermore, `LD_PRELOAD` allows us to specify that our chosen library is loaded into memory **before all others**. We can create a shared library called `example.so` and export it `LD_PRELOAD` as follows, and then check the library dependencies of `/bin/ls`: 
```terminal_session
tokyo:~/LearningC/ # export LD_PRELOAD=$PWD/example.so                                                                     
tokyo:~/LearningC/ # ldd /bin/ls                                                                                            
	linux-gate.so.1 (0xb7fc0000)
	/root/LearningC/example.so (0xb7f8f000)
	libselinux.so.1 => /lib/i386-linux-gnu/libselinux.so.1 (0xb7f43000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7d65000)
	libdl.so.2 => /lib/i386-linux-gnu/libdl.so.2 (0xb7d5f000)
	libpcre.so.3 => /lib/i386-linux-gnu/libpcre.so.3 (0xb7ce6000)
	/lib/ld-linux.so.2 (0xb7fc2000)
	libpthread.so.0 => /lib/i386-linux-gnu/libpthread.so.0 (0xb7cc5000)
```

As you can see, our library at `/root/LearningC/example.so` is loaded first before any other library on disk. ([Awesome explanation](https://www.technovelty.org/linux/a-little-tour-of-linux-gateso.html) of that first library, "`linux-gate.so.1`")

It should be noted that by not specifying a binary after the path to our shared library, `LD_PRELOAD` will use the specified shared library for all dynamically linked programs system wide. 

## /etc/ld.so.preload



