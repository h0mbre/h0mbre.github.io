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
As a way to avoid setting environment variables, we are also allowed to create a text file called `/etc/ld.so.preload` and shared libraries stored in this file delimited by a white space will be `LD_PRELOAD`'d in a sense in the order that they're written, again, system-wide. There is no way to specify a binary this way, this will apply to all dynamically linked programs. We can see that dynamically linked programs check for this file's existence when they are called upon by using the `strace` utility to spy on what system calls a program makes when run. Let's again try `/bin/ls`:
```
tokyo:~/LearningC/ # strace /bin/ls                                                                                        
execve("/bin/ls", ["/bin/ls"], 0xbf8d8e60 /* 47 vars */) = 0
brk(NULL)                               = 0xbc1000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7ed6000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
-----snip-----
```

As you can see, `/bin/ls` calls the `access()` syscall, and checks to see if it has access to `/etc/ld.so.preload`; however, the return value is a `-1` indicating that the file does not exist (`No such file or directory`). 

Let's create the file and then run this excercise again:
```
tokyo:~/LearningC/ # echo "" > /etc/ld.so.preload                                                                           
tokyo:~/LearningC/ # strace /bin/ls                                                                                        
execve("/bin/ls", ["/bin/ls"], 0xbfcba0a0 /* 47 vars */) = 0
brk(NULL)                               = 0x570000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7eff000
access("/etc/ld.so.preload", R_OK)      = 0
openat(AT_FDCWD, "/etc/ld.so.preload", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
-----snip-----
```

This time, we actually get an `openat()` syscall right after `access()` because access finishes with a return value of `0` indicating success. `openat()` returns a value of `3` as a file descriptor.

Let's input our malicious `example.so` library in `/etc/ld.so.preload` and see what `strace` has to say about it. 
```
tokyo:~/LearningC/ # strace /bin/ls                                                                                        
execve("/bin/ls", ["/bin/ls"], 0xbf956640 /* 47 vars */) = 0
brk(NULL)                               = 0x1a8f000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7f64000
access("/etc/ld.so.preload", R_OK)      = 0
openat(AT_FDCWD, "/etc/ld.so.preload", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=27, ...}) = 0
mmap2(NULL, 27, PROT_READ|PROT_WRITE, MAP_PRIVATE, 3, 0) = 0xb7f92000
close(3)                                = 0
openat(AT_FDCWD, "/root/LearningC/example.so", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\360\21\0\0004\0\0\0"..., 512) = 512
```

We see that not only did it open `/etc/ld.so.preload`, it read some values from the file and then opened our shared library for reading. We were able to get our shared library loaded into memory for the run time of `/bin/ls`. 

## Hooking Syscalls with Shared Library Injections
As we have discussed in the `Learning C` progression, this preloading mechanism allows a `root` user to powerfully manipulate userland programs. We can effectively redefine common, frequently-used syscall functions and their higher-level abstraction wrapper functions to mean whatever we arbitrarily desire. If you need more information on this portion of our experiment please consult 




