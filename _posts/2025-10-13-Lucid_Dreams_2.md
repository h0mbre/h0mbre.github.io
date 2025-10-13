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

Because we want to fuzz `nftables`, I decided to implement the syscall itself in a new file called `lucid_fuzz.c` and placed that inside `linux_version/net/netfilter` folder:
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
We want to be able to create stateful inputs for `nftables`. This obviously means we need enough runway initially in our inputs to *build up complex state*! This seems obvious and simple, but I think it's hard to actually implement correctly. We have to consider various things like:
- Not all "state" is "good state": Just because an input can create 4096 `nft_table` data structures, doesn't mean that that's interesting from a vulnerability research perspective
- Short inputs are not likely go create complex state: We need to have somewhat long inputs in order to build up state
- Extremely large inputs may be meaningless: There may not be any meaningful difference between short and long inputs when the short input is *long enough* to create "good state" and we may end up spending tons of CPU cycles doing nothing interesting and working on enormous inputs

With these things in mind, let's first take a cautious approach and make sure we can generate long inputs *some* of the time, but most of the time focus on relatively normal sized inputs. 

### `nftables` Messages
`nftables` expects Netlink messages that are formatted a certain way. It has two modes of messaging as far as I can tell: standalone messages, which are simple messages like "object getters" and batched messages, which are for object creation/modification/deletion. They have gone with a design where anything that can modify state is subject to batching and everything that is read-only can be a standalone message. In the batch mode of operation, `nftables` will have something like a "staging" phase, where it parses the messages in the batch and validates them. While it's validating each individual batched message, it makes sure that the resources being created/manipulated are sane and actually exist and are modifiable. `nftables` will stage all the changes and then if a single message fails in the batch, will attempt to roll back all of those staged changes. If batch message parsing succeeds however, it moves into a "commit" phase and makes the changes. 

So basically, our input generator will need to be capable of sending batches of `nftables` requests with some simple read-only requests sprinkled in rarely. I decided to follow a high level input shape that is very similar to our last blogpost for this purpose. We will do the following:
1. Have Lucid inject a buffer of bytes at a location in Bochs' memory. This is standard and how you want to separate duties between Lucid the fuzzing engine and Lucid's mutators/generators. Let Lucid the fuzzing engine inject a byte blog, let the harness/mutator/generator make sense of the blob. 
2. We will pre-allocate socket buffer structures `skb(s)` in the kernel so that we don't do any large allocations in the fuzzing loop
3. The harness will parse the byte blob, and package each input series from the mutator in an `skb` and ship the `skb` off to `nftables` for parsing
4. We will separate series of `nftables` messages into what we'll call "envelopes". Last blogpost we called them "messages" but because Netlink also operates on "messages" this nomenclature is confusing.

Our input then will contain two different data structures as the harness sees things:
```c
// An input structure
struct lf_input {
	u32 total_len;
	u32 num_envs;
	u8 data[];
};

// An envelope structure
struct lf_envelope {
	u32 len;
	u8 data[];
};
```

This is very similar to our [last blogpost](https://h0mbre.github.io/Lucid_Dreams_1/), but with some key changes to the `envelope` structure. So in practice, an input will always have a single `struct lf_input` structure at its beginning describing the input in its entirety, and then, up to the max number of envelopes, a series of `struct lf_envelope` structures containing the actual Netlink messages for `nftables` in its `data` member. So an input may look like:
```text
[
	[lf_input: total_len=4096, num_msgs=2]
		[lf_envelope: len=2048, <data>]
		[lf_envelope: len=2048, <data>]
]
```

Remember: the core Lucid components know nothing about this structure, Lucid is only responsible for injecting the input and its length into the target at a location in memory. It's up to the mutator and the harness to make sense of the structure. 

So now let's implement the harness with this in mind. It will need to receive the bytes, parse them, wrap each envelope's data in an `skb` and send the `skb` to `nftables`. 

## Reaching `nftables`
The normal path user input takes to `nftables` is something like:
1. userland process creates an `NETLINK_NETFILTER` Netlink socket
2. userland process sends request via `sendmsg` syscall or similar (maybe `sendto`) via the Netlink socket
3. those bytes get wrapped in an `skb` in `netlink_sendmsg`
4. based on the socket's protocol type, `netlink_sendmsg` will find the Netfilter's registered kernel socket that was initialized at kernel boot, the socket has a callback attached to it called `.input` that is to be invoked when there is data ready for it
5. The callback, which points to `nfnetlink_rcv`, is invoked and receives the `skb` holding our data from userland

We can do similar things, but make it more direct since we know the destination in our harness is `nftables`. We can:
1. Pre-allocate `skb` structures to hold our envelopes
2. Parse the `lf_input`, and by included `lf_envelope`:
3. Stuff the envelope's data into an `skb`
4. Send the `skb` directly to `nfnetlink_rcv`
5. Repeat, go back to the 3

## Harness Init Code
Let's go ahead and fill out the logic for the initialization routine of our custom syscall, this is code that will be invoked *once* before we start fuzzing and will not occur in the fuzzing loop. This is code that is meant to set up everything we need for the harness to work appropriately. This is where we will setup the `skbs` and to do so, we'll need to define some constants that describe maximum input shapes. The first constant we need to set is the `MAX_NUM_ENVELOPES`, this is going to tell us how many `struct lf_envelope` structures can exist in an `struct lf_input`. We'll also need to know the `MAX_ENVELOPE_LEN` which will obviously describe how big these envelopes' data payload can be. Finally, as a byproduct of both the maximum number of envelope structures and their maximum length, we'll deduce the `MAX_INPUT_LEN`, which is the largest possible size we can achieve for the `lf_input->total_len` value. 

For now, let's go ahead and say that we can have up to 24 envelopes, and each one can be up to 8192 bytes. In the mutator, well define min/max thresholds where we mostly uniformly distribute size selection between those two thresholds with a small possibility of going lower or higher than them. So most of the time we'll do at least 8 envelopes and less than or exactly 16 envelopes. Something like that. We'll make 1-7 and 17-24 very rare. Same with the sizes, well try not to send an insane amount of `nftables` messages per envelope and approach the 8k max. But this is for a later blogpost on the mutator. 

With the constants in mind we can build. We can do all of this in `af_netlink.c` in `/net/netlink` because it has all of the things we need access to and makes everything easy. So we'll implement `lf_init` in there, which means we need access to `lucid_init` in our `lucid_fuzz.c` stand alone source file, so we'll change that to:
```c
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

// These will be defined in /include/net/lucid_fuzz.h
extern int lucid_init(const void __user *data, size_t len);

SYSCALL_DEFINE2(lucid_fuzz, const void __user *, data, size_t, len)
{
    int ret = 0;

    printk("Inside lucid fuzz!\n");
    printk("Calling lucid_init...\n");
    ret = lucid_init(data, len);
    if (ret)
        goto done;

done:
	return ret;
}
```

Now we'll need to create that header file in `/include/net/lucid_fuzz.h`:
```c
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_LUCID_FUZZ_H
#define _NET_LUCID_FUZZ_H

int lucid_init(const void __user *data, size_t len);

#endif /* _NET_LUCID_FUZZ_H */
```
