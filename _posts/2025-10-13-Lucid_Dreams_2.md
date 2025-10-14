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
extern int lucid_fuzz_init(const void __user *data, size_t len);

SYSCALL_DEFINE2(lucid_fuzz, const void __user *, data, size_t, len)
{
    int ret = 0;

    printk("Inside lucid fuzz!\n");
    printk("Calling lucid_fuzz_init...\n");
    ret = lucid_fuzz_init(data, len);
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

int lucid_fuzz_init(const void __user *data, size_t len);

#endif /* _NET_LUCID_FUZZ_H */
```

Now we can include that header in `af_netlink.c`. And we get started in that source file with our defines of our constants we discussed:
```c
/*************** Start of Lucid Fuzzing Harness *****************************/
#define LF_MAX_NUM_ENVS 24UL // Number of envelopes in an input
#define LF_MAX_ENV_LEN 8192UL // Number of bytes in an envelope payload 
#define LF_INPUT_HDR_SIZE (sizeof(u32) * 2) // lf_input->total_len, num_envs
#define LF_ENV_HDR_SIZE (sizeof(u32)) // lf_envelope->len
#define LF_MAX_TOTAL_ENV ((LF_MAX_ENV_LEN + LF_ENV_HDR_SIZE) * LF_MAX_NUM_ENVS)
#define LF_MAX_INPUT_LEN (LF_MAX_TOTAL_ENV + LF_INPUT_HDR_SIZE)
```

Next, I defined the `LUCID_SIGNATURE` that Lucid scans for when trying to decide where to inject inputs. It knows the layout of the `struct lf_fuzzcase` so it knows that directly after the signature portion it has a length field and then the variable length data field where it inserts the raw bytes:
```c
// Structure that describes an input as Lucid sees it
struct lf_fuzzcase {
	unsigned char signature[16];
	size_t input_len;
	u8 input[LF_MAX_INPUT_LEN];
};

// Create instance of the struct
struct lf_fuzzcase fc = {
	.signature = LUCID_SIGNATURE,
	.input_len = 0,
	.input = { 0 }	/* Where Lucid injects an input */
};
```

Then we define some globals that we need to initialize:
-`handler`: This is a function pointer basically to the `nfnetlink_rcv` function that we look up by protocol in the `init` namespace
-`kern_sock`: This is the `struct sock` that is registered during kernel boot for the Netfilter subsystem to receive data from userland (and I guess kernel threads?)
- `skbs`: Just a flat buffer of the `skb` structures we'll need to use to wrap our envelope data, the harness exchanges envelopes by `skb` structures

Finally the initialization routine is thus:
```c
// The function pointer we send the skbs to, the netlink rcv handler for
// netfilter nfnetlink_rcv
void *handler = NULL;

// The kernel-registered socket waiting for input from us
struct sock *kern_sock = NULL;

// Pool of skbs we use to store data in envelopes
struct sk_buff *skbs[LF_MAX_NUM_ENVS] = { 0 }; 

// Our initialization function, called before we do any fuzzing
int lucid_fuzz_init(const void __user *data, size_t len) {
	int err = 0;
	int i = 0;
	struct sk_buff *skb = NULL;

	printk("Hello from lucid_fuzz_init\n");
	printk("LF_MAX_INPUT_LEN is: %lu\n", LF_MAX_INPUT_LEN);

	// Copy the user data over to the fuzzcase instance if there is any
	if (len > 0 && len <= LF_MAX_INPUT_LEN) {
		if (copy_from_user(
			fc.input, data, len
		))
		{
			err = -EFAULT;
			goto done;
		}
		fc.input_len = len;
	}

	// Doing this how other kernel code does it, lock the global table
	netlink_table_grab();

	// Pre-set the err as if we failed to find the handler for NETFILTER
	err = -ENOENT;

	// Check to see if the handler is registered
	if (!nl_table[NETLINK_NETFILTER].registered) {
		netlink_table_ungrab();
		goto done;
	}

	// Grab the kernel socket
	kern_sock = netlink_lookup(&init_net, NETLINK_NETFILTER, 0);
	if (!kern_sock) {
		netlink_table_ungrab();
		goto done;
	}

	// Grab that .input handler
	handler = nlk_sk(kern_sock)->netlink_rcv;
	if (!handler) {
		netlink_table_ungrab();
		goto done;
	}

	// Ungrab the table we're done with it
	netlink_table_ungrab();

	// Pre-set
	err = -ENOMEM;

	// Create all of the socket buffers we need and store them
	for (i = 0; i < LF_MAX_NUM_ENVS; i++) {
		skb = alloc_skb(LF_MAX_ENV_LEN, GFP_KERNEL);
		// If we failed, unroll all the previous allocations
		if (!skb) {
			while (--i >= 0) {
				kfree_skb(skbs[i]);
				skbs[i] = NULL;
			}
			goto done;
		}

		// Initialize what we need to look legit
		skb->pkt_type = PACKET_HOST;
        skb->sk = kern_sock;
		NETLINK_CB(skb).portid = 0x1337;
		NETLINK_CB(skb).dst_group = 0;
		NETLINK_CB(skb).creds.uid = GLOBAL_ROOT_UID;
		NETLINK_CB(skb).creds.gid = GLOBAL_ROOT_GID;
		NETLINK_CB(skb).flags = NETLINK_SKB_DST;

		// Store the skb
		skbs[i] = skb;
	}

	// We are so done dude, it worked
	err = 0;

done:
	return err;
}
```

This should initialize all of the structures we need to start actually parsing inputs and dispatching them in the main harness function. 

## Main Parsing Routine
We've reached the point now where the input buffer global is loaded with data and we know the address of the function to invoke to dispatch the data to Netfilter. We've also initialized the socket buffers we're going to use to do the transportation. We need to describe what an input looks like, so let's define our input structures. 
```c
// Define our input structures
struct lf_input {
	u32 total_len;
	u32 num_envs;
	u8 data[];
};

struct lf_envelope {
	u32 len;
	u8 data[];
};
```

The first thing we do in the main loop is take the snapshot that Bochs will save to disk. The Lucid workflow is something like:
1. develop environment, harness
2. put a special NOP operation in the harness where you want to snapshot fuzz from (`xchg dx, dx`)
3. run the environment/harness in the `gui-bochs`. This is relatively normal Bochs binary built with GUI support that is supposed to be user-friendly and allow you to dump this Bochs snapshot to disk
4. the Rust fuzzer binary, `lucid-fuzz` can then take that Bochs snapshot on disk, and resume its execution with a purpose-built `lucid-bochs` binary. This will call into the Lucid fuzzer before it emulates the first instruction and create a new kind of snapshot that Lucid can understand and restore every fuzzing iteration. 

Below is the code I've added to Bochs to save the Bochs snapshot to disk when we encounter the `xchg dx, dx` NOP, where `i` is a variable name for the instruction structure:
```c++
#if BX_SNAPSHOT
  // Check for take snapshot instruction `xchg dx, dx`
  if ((i->src() == i->dst()) && (i->src() == 2)) {
    BX_COMMIT_INSTRUCTION(i);
    if (BX_CPU_THIS_PTR async_event)
      return;
    ++i;
    char save_dir[] = "/tmp/lucid_snapshot";
    mkdir(save_dir, 0777);
    printf("Saving Lucid snapshot to '%s'...\n", save_dir);
    if (SIM->save_state(save_dir)) {
      printf("Successfully saved snapshot\n");
      sleep(2);
      exit(0);
    }
    else {
      printf("Failed to save snapshot\n");
    }
    BX_EXECUTE_INSTRUCTION(i);
  }
#endif
```

Then we get around to making sure we have enough bytes to form the metadata structure (`lf_input`) and sanity check its values before moving on to the nested envelopes. You'll notice that all error paths are `return 1;`, this is so that during fuzzing and mutator development, we skip over the snapshot restore NOP instruction at the end of the main fuzzing loop in the harness. This cascade of timeouts will let us know that we have a bug in our mutator. Here is the main loop:
```c
// Main input processing logic
int lucid_fuzz_handle_input(void) {
	struct lf_input *input = NULL;
	struct lf_envelope *env = NULL;
	struct sk_buff *fuzz_skb = NULL;
	u32 remaining = 0;
	u32 offset = 0;

	printk("Hello from lucid_fuzz_handle_input\n");

	/** LUCID TAKES SNAPSHOT HERE **/
	// This special NOP instruction, when interpreted by Bochs will cause
	// Bochs to save a snapshot of its state to disk that Lucid will be able
	// to resume in its purpose built version of Bochs called `lucid_bochs`
	asm volatile("xchgw %dx, %dx");

	// Make sure we enough bytes to construct the input metadata
	if (fc.input_len < sizeof(lf_input))
		return 1;

	// Cast the data to our metadata struct
	input = (struct lf_input *)fc.input;

	// Sanity check the values
	if (input->total_len != fc.input_len || input->total_len > LF_MAX_INPUT_SIZE)
		return 1;

	// Sanity check the number of messages
	if (input->num_msgs > LF_MAX_NUM_ENVS || input->num_msgs == 0)
		return 1;

	// Check how many remaining bytes we have, and subtract what we already
	// consumed with the input metadata
	remaining = input->total_len;
	remaining -= LF_INPUT_HDR_SIZE;

	// Start tracking an offset into the byte buffer where we're reading from
	offset = LF_INPUT_HDR_SIZE;
```

Then we can start iterating through envelopes and parsing them. Each successfully parsed envelope gets turned into an `skb` and dispatched to `nftables`:
```c
// Iterate through the envelopes and parse each one
	for (i = 0; i < input->num_envs; i++) {
		// Make sure we have enough data remaining to parse an envelope metadata
		if (remaining < LF_ENV_HDR_SIZE)
			return 1;

		// We can at least read the length field, and sanity check it
		env = (struct lf_envelope *)(fc.input + offset);
		if (env->len > LF_MAX_MSG_SIZE || env->len == 0)
			return 1;

		// Consume those bytes
		remaining -= LF_ENV_HDR_SIZE;

		// Make sure we can read that much data
		if (remaining < env->len)
			return 1;

		// We have enough data left, create the skb for this envelope
		fuzz_skb = create_fuzz_skb(env, i);
		if (!fuzz_skb)
			return 1;

		// Dispatch the fuzz_skb to nftables!
		dispatch_skb(fuzz_skb);

		// Update our offset
		offset += (LF_ENV_HDR_SIZE + env->len);

		// Update remaining
		remaining -= env->len;

	}
```

We initialize the `fuzz_skb` in this function. This is where we set the socket buffer up with all the information we need to successfully get received and parsed by `nftables`. We exchange the "envelope" wrapper for the socket buffer wrapper instead:
```c
// Creates a socket buffer filled with fuzz message
static struct sk_buff *create_fuzz_skb(struct lf_envelope *env, int idx) {
	struct sk_buff *skb = NULL;

	// Sanity check
	if (idx >= LF_MAX_NUM_ENVS)
		return NULL;

	// Grab socket buffer from global buf
	skb = skbs[idx];

	// Set the socket buffer's sock to the kernel sock for Netfilter
	skb->sk = kern_sock;

	// Inject fuzz data and set sizes
	memcpy(skb_put(skb, env->len), env->data, env->len);

	return skb;
}
```

The dispatching of the `skb` is simple, we just cast the `handler` to the right function pointer signature and then invoke it with the skb:
```c
// Dispatches the skb to the appropriate netlink recv handler
static void dispatch_skb(struct sk_buff *skb) {
	// Create function pointer, msg->protocol already sane
	void (*rcv)(struct sk_buff *) = handler;

	// Dispatch!
	rcv(skb);
}
```

The main fuzzing loop then of course restores the snapshot after we're done parsing envelopes:
```c
// Done parsing envelopes, check if we have remaining bytes
	if (remaining)
		return 1;

	/** LUCID RESTORES SNAPSHOT **/
	asm_volatile("xchgw %bx, %bx");

	// Finally done
	return 0;
```

We'll save the rest of the snippets for the source files I'll post at the end. 

## Testing Harness
Everything is wired up, so now we can send inputs via the `harness` userland binary we compiled. Let's check out `strace` on the `nft` userland utility and see where the Netlink message to create an `nft_table` is sent over the Netlink socket. Our `nft` command is: `nft add table inet fuzz`:
```terminal
// Create the Netlink socket of the protocol type NETLINK_NETFILTER
socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) = 3

// Send the Netlink message to create a table over that socket fd we just created
sendto(3, [{nlmsg_len=20, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_GETGEN, nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}, {nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(0)}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20
recvmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base=[{nlmsg_len=44, nlmsg_type=NFNL_SUBSYS_NFTABLES<<8|NFT_MSG_NEWGEN, nlmsg_flags=0, nlmsg_seq=0, nlmsg_pid=125392}, {nfgen_family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(103)}, [[{nla_len=8, nla_type=0x1}, "\x00\x00\x00\x67"], [{nla_len=8, nla_type=0x2}, "\x00\x01\xe9\xd0"], [{nla_len=8, nla_type=0x3}, "\x6e\x66\x74\x00"]]], iov_len=69631}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 44
```

So it happens during `sendmsg` syscall, so what I did was just write an `LD_PRELOAD` shared object to hexdump the iovec data sent over `sendmsg`. So now I can get a `hexdump -C` style output for the `nft` message:
```terminal
LD_PRELOAD=$PWD/hexdump_netlink.so nft add table inet fuzz
00000000  14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00 |................|
00000010  00 00 0a 00 28 00 00 00  00 0a 01 00 01 00 00 00 |....(...........|
00000020  00 00 00 00 01 00 00 00  09 00 01 00 66 75 7a 7a |............fuzz|
00000030  00 00 00 00 08 00 02 00  00 00 00 00 14 00 00 00 |................|
00000040  11 00 01 00 02 00 00 00  00 00 00 00 00 00 0a 00 |................|
```

Now we know what a legit `nftables` message looks like and we can wrap it in our `lf_input` and `lf_envelope` structures and test the harness! I took that output and just hardcoded it into a janky Python script to dump the binary to the terminal:
```python
import struct
import sys

# Dumped message
msg_str = [
    "00000000  14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00 |................|",
    "00000010  00 00 0a 00 28 00 00 00  00 0a 01 00 01 00 00 00 |....(...........|",
    "00000020  00 00 00 00 01 00 00 00  09 00 01 00 66 75 7a 7a |............fuzz|",
    "00000030  00 00 00 00 08 00 02 00  00 00 00 00 14 00 00 00 |................|",
    "00000040  11 00 01 00 02 00 00 00  00 00 00 00 00 00 0a 00 |................|"
]

# Byte string we'll fill
all_bytes = b''
for line in msg_str:
    # Skip the offset stuff
    hex_start = line[10:]

    # Cut off the back ascii stuff
    hex_str = hex_start[:len(hex_start) - 18]

    # Remove the spaces
    hex_str = hex_str.replace(" ", "")

    # Start appending
    all_bytes += bytes.fromhex(hex_str)

# Now with bytes, wrap that in envelope
envelope_len = len(all_bytes)
envelope = struct.pack('<I', envelope_len) + all_bytes

# Now wrap that in an lf_input
num_envs = 1
total_len = 8 # Metadata for lf_input
total_len += len(envelope)
lf_input = struct.pack('<II', total_len, num_envs) + envelope

# Write that to stdout
sys.stdout.buffer.write(lf_input)
```

We can now pipe that to `base64` and then pipe that to the harness for testing:
```terminal
[devbox:~/nft_fuzzing]$ python3 wrapper.py | base64
XAAAAAEAAABQAAAAFAAAABAAAQAAAAAAAAAAAAAACgAoAAAAAAoBAAEAAAAAAAAAAQAAAAkAAQBmdXp6AAAAAAgAAgAAAAAAFAAAABEAAQACAAAAAAAAAAAACgA=
```

Then when we run `echo "<base64>" | harness` on the `qemu-system` running our custom kernel, we get the following kernel logs:
```terminal
[   23.347957] Inside lucid fuzz!
[   23.349015] Calling lucid_fuzz_init...
[   23.350233] Hello from lucid_fuzz_init
[   23.351399] LF_MAX_INPUT_LEN is: 196712
[   23.355266] Hello from lucid_fuzz_handle_input
[   23.359789] Calling lucid_fuzz_cleanup...
lucid_fuzz returned 0
```

So the harness works! 

## Conclusion
Hopefully this helps you understand how to write a harness for Lucid. We needed to:
1. identify a way to inject raw input bytes into kernel memory
2. take a snapshot with our special NOP instruction
3. implement a custom protocol that our harness can understand so that it can parse the raw input bytes into something that can be sent to the target
4. reset the snapshot with our special NOP instruction
5. cleanup all the resources in the harness so we can use it for debugging as well. 

I've pasted the full harness code that I added in `af_netlink.c` below, cheers:
```c
/*************** Start of Lucid Fuzzing Harness *****************************/
#define LF_MAX_NUM_ENVS 24UL // Number of envelopes in an input
#define LF_MAX_ENV_LEN 8192UL // Number of bytes in an envelope payload 
#define LF_INPUT_HDR_SIZE (sizeof(u32) * 2) // lf_input->total_len, num_envs
#define LF_ENV_HDR_SIZE (sizeof(u32)) // lf_envelope->len
#define LF_MAX_TOTAL_ENV ((LF_MAX_ENV_LEN + LF_ENV_HDR_SIZE) * LF_MAX_NUM_ENVS)
#define LF_MAX_INPUT_LEN (LF_MAX_TOTAL_ENV + LF_INPUT_HDR_SIZE)

// Used by Lucid when scanning for where to inject the input 
#define LUCID_SIGNATURE { 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, \
                          0x13, 0x38, 0x13, 0x38, 0x13, 0x38, 0x13, 0x38 }

// Structure that describes an input as Lucid sees it
struct lf_fuzzcase {
	unsigned char signature[16];
	size_t input_len;
	u8 input[LF_MAX_INPUT_LEN];
};

// Create instance of the struct
struct lf_fuzzcase fc = {
	.signature = LUCID_SIGNATURE,
	.input_len = 0,
	.input = { 0 }	/* Where Lucid injects an input */
};

// The function pointer we send the skbs to, the netlink rcv handler for
// netfilter nfnetlink_rcv
void *handler = NULL;

// The kernel-registered socket waiting for input from us
struct sock *kern_sock = NULL;

// Pool of skbs we use to store data in envelopes
struct sk_buff *skbs[LF_MAX_NUM_ENVS] = { 0 }; 

// Our initialization function, called before we do any fuzzing
int lucid_fuzz_init(const void __user *data, size_t len) {
	int err = 0;
	int i = 0;
	struct sk_buff *skb = NULL;

	printk("Hello from lucid_fuzz_init\n");
	printk("LF_MAX_INPUT_LEN is: %lu\n", LF_MAX_INPUT_LEN);

	// Copy the user data over to the fuzzcase instance if there is any
	if (len > 0 && len <= LF_MAX_INPUT_LEN) {
		if (copy_from_user(
			fc.input, data, len
		))
		{
			err = -EFAULT;
			goto done;
		}
		fc.input_len = len;
	}

	// Doing this how other kernel code does it, lock the global table
	netlink_table_grab();

	// Pre-set the err as if we failed to find the handler for NETFILTER
	err = -ENOENT;

	// Check to see if the handler is registered
	if (!nl_table[NETLINK_NETFILTER].registered) {
		netlink_table_ungrab();
		goto done;
	}

	// Grab the kernel socket
	kern_sock = netlink_lookup(&init_net, NETLINK_NETFILTER, 0);
	if (!kern_sock) {
		netlink_table_ungrab();
		goto done;
	}

	// Grab that .input handler
	handler = nlk_sk(kern_sock)->netlink_rcv;
	if (!handler) {
		netlink_table_ungrab();
		goto done;
	}

	// Ungrab the table we're done with it
	netlink_table_ungrab();

	// Pre-set
	err = -ENOMEM;

	// Create all of the socket buffers we need and store them
	for (i = 0; i < LF_MAX_NUM_ENVS; i++) {
		skb = alloc_skb(LF_MAX_ENV_LEN, GFP_KERNEL);
		// If we failed, unroll all the previous allocations
		if (!skb) {
			while (--i >= 0) {
				kfree_skb(skbs[i]);
				skbs[i] = NULL;
			}
			goto done;
		}

		// Initialize what we need to look legit
		skb->pkt_type = PACKET_HOST;
		skb->sk = kern_sock;
		NETLINK_CB(skb).portid = 0x1337;
		NETLINK_CB(skb).dst_group = 0;
		NETLINK_CB(skb).creds.uid = GLOBAL_ROOT_UID;
		NETLINK_CB(skb).creds.gid = GLOBAL_ROOT_GID;
		NETLINK_CB(skb).flags = NETLINK_SKB_DST;

		// Store the skb
		skbs[i] = skb;
	}

	// We are so done dude, it worked
	err = 0;

done:
	return err;
}

// Define our input structures
struct lf_input {
	u32 total_len;
	u32 num_envs;
	u8 data[];
};

struct lf_envelope {
	u32 len;
	u8 data[];
};

// Creates a socket buffer filled with fuzz message
static struct sk_buff *create_fuzz_skb(struct lf_envelope *env, int idx) {
	struct sk_buff *skb = NULL;

	// Sanity check
	if (idx >= LF_MAX_NUM_ENVS)
		return NULL;

	// Grab socket buffer from global buf
	skb = skbs[idx];

	// Set the socket buffer's sock to the kernel sock for Netfilter
	skb->sk = kern_sock;

	// Inject fuzz data and set sizes
	memcpy(skb_put(skb, env->len), env->data, env->len);

	return skb;
}

// Dispatches the skb to the appropriate netlink recv handler
static void dispatch_skb(struct sk_buff *skb) {
	// Create function pointer, msg->protocol already sane
	void (*rcv)(struct sk_buff *) = handler;

	// Dispatch!
	rcv(skb);
}

// Main input processing logic
int lucid_fuzz_handle_input(void) {
	int i = 0;
	struct lf_input *input = NULL;
	struct lf_envelope *env = NULL;
	struct sk_buff *fuzz_skb = NULL;
	u32 remaining = 0;
	u32 offset = 0;
	struct sock *blegh = NULL;

	printk("Hello from lucid_fuzz_handle_input\n");
	blegh = kern_sock;
	printk("kern_sock->net: %p\n", sock_net(kern_sock));

	/** LUCID TAKES SNAPSHOT HERE **/
	// This special NOP instruction, when interpreted by Bochs will cause
	// Bochs to save a snapshot of its state to disk that Lucid will be able
	// to resume in its purposbe built version of Bochs called `lucid_bochs`
	asm volatile("xchgw %dx, %dx");

	// Make sure we enough bytes to construct the input metadata
	if (fc.input_len < sizeof(struct lf_input))
		return 1;

	// Cast the data to our metadata struct
	input = (struct lf_input *)fc.input;

	// Sanity check the values
	if (input->total_len != fc.input_len || input->total_len > LF_MAX_INPUT_LEN)
		return 1;

	// Sanity check the number of messages
	if (input->num_envs > LF_MAX_NUM_ENVS || input->num_envs == 0)
		return 1;

	// Check how many remaining bytes we have, and subtract what we already
	// consumed with the input metadata
	remaining = input->total_len;
	remaining -= LF_INPUT_HDR_SIZE;

	// Start tracking an offset into the byte buffer where we're reading from
	offset = LF_INPUT_HDR_SIZE;

	// Iterate through the envelopes and parse each one
	for (i = 0; i < input->num_envs; i++) {
		// Make sure we have enough data remaining to parse an envelope metadata
		if (remaining < LF_ENV_HDR_SIZE)
			return 1;

		// We can at least read the length field, and sanity check it
		env = (struct lf_envelope *)(fc.input + offset);
		if (env->len > LF_MAX_ENV_LEN || env->len == 0)
			return 1;

		// Consume those bytes
		remaining -= LF_ENV_HDR_SIZE;

		// Make sure we can read that much data
		if (remaining < env->len)
			return 1;

		// We have enough data left, create the skb for this envelope
		fuzz_skb = create_fuzz_skb(env, i);
		if (!fuzz_skb)
			return 1;

		// Dispatch the fuzz_skb to nftables!
		dispatch_skb(fuzz_skb);

		// Update our offset
		offset += (LF_ENV_HDR_SIZE + env->len);

		// Update remaining
		remaining -= env->len;
	}

	// Done parsing envelopes, check if we have remaining bytes
	if (remaining)
		return 1;

	/** LUCID RESTORES SNAPSHOT **/
	asm volatile("xchgw %bx, %bx");

	// Finally done
	return 0;
}

// Cleanup resources from lf_init(), not used when fuzzing but good for harness
// dev/testing
void lucid_fuzz_cleanup(void) {
	int i = 0;

	for (i = 0; i < LF_MAX_NUM_ENVS; i++) {
		kfree_skb(skbs[i]);
		skbs[i] = NULL;
	}

	// NULL the globals
	kern_sock = NULL;
	handler = NULL;

	// Set input size to 0
	fc.input_len = 0;
}
```
