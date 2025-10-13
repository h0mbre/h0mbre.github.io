---
layout: post
title: "Lucid Dreams II: Harness Development"
date: 2025-10-13
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Fuzzing
  - Linux
  - Kernel
  - Nftables
---

## Background
Last episode on the blog we took a shallow and broad approach to fuzzing several Netlink-plumbed subsystems like Netfilter, Route, Crypto, and Xfrm. This endeavor wasn't necessarily an earnest bug finding mission since we mostly wanted to just see how fuzzing a real target with Lucid would go and what things would need tweaking. We ended up changing quite a bit of the core-fuzzer features, specifically Redqueen issues, and were able to improve the fuzzer quite a bit. We modularized the mutator component of Lucid so now writing your own fuzzer for Lucid is as simple as implementing your own mutator. We can extend this even more, and will, by enabling the user to pass command line arguments directly to the bespoke mutator.

So now you can conceive of the main Lucid core components as a fuzzing engine and the mutator as the "fuzzer" because it is responsible for all of the target-specific characteristics. So for example, if we were to fuzz Chrome in Lucid, you would write a "Chrome fuzzer" by implementing your own fuzzing harness for Chrome and then implementing your own mutator to generate and mutate inputs.

We now switch to a more earnest bug finding mode of operation. I've decided for this series to focus on fuzzing [`nftables`](https://en.wikipedia.org/wiki/Nftables) for a few different reasons:
- `nftables` doesn't have as many eyeballs on it anymore, at least publicly, because kCTF has changed its rules around unprivileged usernamespaces which as severely decreased the value of exploitable bugs in surfaces that live behind those namespaces, so less competition
- `nftables` is extremely complex. There are serveral hierarchical structures and states that can occur and in addition, the code exists on two planes: a configuration plane responsible for creating these nested and complex resources and a data plane responsible for interacting with those created structures. For the early going, we're going to be focusing exclusively on the control plane with designs on implementing data plane interactions later
- `nftables` has a history of bugs, so much so that it was explicitly disabled in kCTF's bounty program
- Syzkaller fuzzes `nftables` already, but if you look at the types of messages it is able to generate, it tends to favor syntactically-valid but semantically-invalid inputs. For instance, it will send a well-formed message to create a resource, but the argument values themselves may be nonsense. Further, syzkaller currently has no way to track the state of resources if they were successfully created. So sequences like create resource -> modify resource -> use resource -> destroy resource are not possible currently unless they happen by sheer random chance which is highly unlikely
- lastly, this represents a fun engineering challenge. Creating a mutator/generator that is able to achieve deep stateful coverage of `nftables` will be something unique as far as public research goes I think

## Adding Custom Syscall
The first thing we need is a way to interact with the `nftables` subsystem. My goto strategy here is to just create a custom syscall that usually takes a userland buffer pointer and a data length. This allows us to send an input from userland and have it traverse the harness and then hit the target subsystem. Now, this is not how I want to *fuzz*, but it is a useful setup for debugging, collecting coverage metrics for visualization, and also reproducing crashes. Ideally the flow looks like this:
1. Send data buffer via syscall
2. Context-switch to kernel mode as harness is about to parse input
3. [FUZZING-ONLY] Take snapshot
4. Harness parses input and dispatches to target subsystem
5. [FUZZING-ONLY] Reset snapshot
6. Return to userland

This setup gives us the best of both worlds, we can easily debug and play with our harness from userland and we can also fuzz completely in kernel context without having to emulate any expensive context switches per fuzzcase. 

To add a new syscall, we have to edit the `syscall_64.tbl` file found in `linux_version/arch/x86/entry/syscalls`, wherein I added a new syscall entry right after the last syscall entry:
```c
...
466	common	removexattrat		sys_removexattrat
467	common	open_tree_attr		sys_open_tree_attr
468	common	file_getattr		sys_file_getattr
469	common	file_setattr		sys_file_setattr
470 common  lucid_fuzz          sys_lucid_fuzz
```

Now we have to define it in the `linux_version/include/linux/syscalls.h` file:
```c
...
asmlinkage long sys_geteuid16(void);
asmlinkage long sys_getgid16(void);
asmlinkage long sys_getegid16(void);
asmlinkage long sys_lucid_fuzz(const void __user *data, size_t len);
```

Because we want to fuzz `nftables`, I decided to implement the syscall itself in a new file called `lucid_fuzz.c` and placed that inside `linux_version/net/netfilter` folde:
```c
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

SYSCALL_DEFINE2(lucid_fuzz, const void __user *, data, size_t, len)
{
    printk("Inside lucid fuzz!\n");
	return 0;
}
```

Now we have to tell the kernel to compile this source file. This is accomplished by editing the folder's `Makefile` to ensure that our `lucid_fuzz.c` file is used to create an object file. I changed the top line of the `Makefile` in my kernel version `6.17` to this:
```text
netfilter-objs := core.o nf_log.o nf_queue.o nf_sockopt.o utils.o lucid_fuzz.o
```

When we build the kernel, we should see this in the output
```text
  CC      net/netfilter/lucid_fuzz.o
```

To interact with the syscall, we'll need a userland program. This is a small program to read data from standard in (easy to use in the future to reproduce crashes or replay fuzzing inputs) and then send that data via the syscall to the kernel:
```c
// gcc harness.c -o harness -static
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifndef __NR_lucid_fuzz
#define __NR_lucid_fuzz 470 // Our syscall number
#endif

int main(void) {
    // Start at a page, we'll double this if we need more memory
    size_t cap = 4096;
    size_t len = 0;
    const size_t MAX_CAP = 64 * 1024 * 1024; // Shouldn't need more than this?

    // Create a buffer to hold data
    uint8_t *buf = malloc(cap);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    // Read until we can't
    while (1) {
        // Grab data from standard in, taking into account the offset as determined
        // by `len`
        ssize_t n = read(STDIN_FILENO, buf + len, cap - len);

        // If we got bytes...
        if (n > 0) {
            // Adjust offset
            len += (size_t)n;

            // See if we hit the current cap
            if (len == cap) {

                // Hit sanity check, bail
                if (cap >= MAX_CAP) {
                    fprintf(stderr, "refusing to grow beyond %zu bytes\n", MAX_CAP);
                    free(buf);
                    return 1;
                }

                // Create new backing buffer
                size_t ncap = cap * 2;

                // Lol 
                if (ncap <= cap) {
                    fprintf(stderr, "size overflow\n");
                    free(buf);
                    return 1;
                }

                // Make sure we didn't do an oopsie
                if (ncap > MAX_CAP) ncap = MAX_CAP;
                uint8_t *tmp = realloc(buf, ncap);
                if (!tmp) {
                    perror("realloc");
                    free(buf);
                    return 1;
                }

                // Update 
                buf = tmp;
                cap = ncap;
            }
            continue;
        }

        // Done reading: EOF
        if (n == 0) break;

        // Failed to read but just because of an interrupt, try again
        if (n < 0 && errno == EINTR) continue;
        
        // Bail on any other errors
        if (n < 0) {
            perror("read");
            free(buf);
            return 1;
        }
    }

    // Call our custom syscall 
    long ret = syscall(__NR_lucid_fuzz, buf, (size_t)len);

    // Need to make sure that our syscall returns meaningful data on error
    if (ret == -1) {
        int e = errno;
        fprintf(stderr, "lucid_fuzz failed: %s\n", strerror(e));
        free(buf);
        return 1;
    }

    printf("lucid_fuzz returned %ld\n", ret);
    free(buf);
    return 0;
}
```

Now we can test in `qemu-system`:
```terminal
root@syzkaller:~# echo "lol" | harness
[  256.492957] Inside lucid fuzz!
lucid_fuzz returned 0
root@syzkaller:~# 
```

So everything works with the syscall, now it's time to make it an actual fuzzing harness. 

## Deciding Input Format
