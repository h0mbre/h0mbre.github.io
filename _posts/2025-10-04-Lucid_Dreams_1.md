---
layout: post
title: "Lucid Dreams I: Lucid's First Time Fuzzing"
date: 2025-10-04
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Fuzzing
  - Linux
  - Kernel
  - Netlink
---

## Background
We've spent a lot of time so far on this blog documenting the development process of Lucid, our full-system snapshot fuzzer, and I really wanted to start using it to do some real fuzzing. So the focus of this blog post will be documenting the process I had to take to get Lucid up and fuzzing on a real target. So far, Lucid has only worked on a toy harness/example, and so we need to see what kind of things need tweaking when a real target comes into play.

## Off-Blog Snapshot Dev
Since the last post, the biggest change has been the way we do snapshots. I found that on the simple development target, a really tight fuzzing loop, the scaling factor for the old snapshot method deteriorated quickly.

### Old Snapshot Method Revisited
If you remember, the fuzzer works by loading a `static-pie` ELF image of the Bochs x86 emulator into the fuzzer process and context switching between the now sand-boxed emulator that runs our target and our fuzzer which does all the fuzzy things. Because we load and sand-box Bochs, we know the location of every memory segment in the image that is writable, as well as where the dynamic memory is because we don't allow Bochs to interface with the OS to allocate memory, the fuzzer handles that. So what we did was map the writable memory segments such that they were all contiguous in memory. Then when we take a snapshot of Bochs, all we have to do is capture that memory state and save it off. We did that, and we saved the memory as a memory-backed file. On Linux, snapshot restoration then becomes very simple, we just `mmap` that memory backed file back over top the contiguous writable memory region. One single syscall to restore memory. We did this mainly because it was very simple. Well it turns out, when you ask the kernel to invalidate/destroy/and overwrite billions of bytes worth of pages thousands of times per second, it scales poorly. Embarrassed to admit that I don't quite remember what the bottleneck was, but I seem to remember that the `mmap` requests seemed to need some sort of serialization and were spending most of their CPU time destroying the dirtied memory backing pages. My scaling factor went into the toilet once I brought up the 8 cores I have on my devbox. So I had to find another way to do this, likely one that didn't depend on restoring *all* writable memory each iteration, but differentially resetting only dirty memory in Bochs. 

### New Strategy for Linear Scaling
We want to be able to scale Lucid linearly as we bring more cores online for fuzzing, so we want our scaling factor to be one-to-one with the amount of cores being used. 100 cores should bring us a 100x speed-up over single-core fuzzing. So we need a way to differentially restore only the dirty memory and not all writable memory. We also want to strive for a method that doesn't invoke the kernel via syscall, because that's how you bottleneck across cores. The way I decided to do this is not novel and I didn't invent this method, it's actually similar to the way a lot of fuzzers get coverage feedback on black-box targets.

What I ended up doing is marking all of the writable pages that we load for Bochs as having no write permissions (strictly `PROT_READ`). This way, when Bochs tries to write to a page, it will cause a page-fault. On Linux, your process gets a signal delivered whenever this happens and you can invoke a function to handle signals. So I patched Bochs to handle these page faults and in the signal handler function Bochs marks the faulting address as a dirty page in a data structure that both Bochs and Lucid have access to. So now, we've logged a page that was dirtied and we then make that page permanently writable and we restore that page on snapshot reset every time now. This design boils snapshot restoration down to a series of `memcpy` calls from the snapshot memory to the dirty memory. Now we've achieved differential restoration and everything is done purely in userspace via `memcpy`, no syscalls are invoked in the hot path to restore the snapshot. This seems to scale perfectly and we're pretty close to the one-to-one scaling factor we're after. The fuzzers spend 100% of their time in userland when they're executing the hot fuzzing loops. 

```text
┌──────────────────────────────────────────────┐
│ [1] Fuzzcase Begins                          │◀─┐
│ Lucid starts executing target code in Bochs. │  │
└──────────────────────────────┬───────────────┘  │
                               │                  │
                               ▼                  │
┌──────────────────────────────────────────────┐  │
│ [2] Bochs Writes to Page                     │  │
│ Attempted write → page is PROT_READ only.    │  │
└──────────────────────────────┬───────────────┘  │
                               │                  │
                               ▼                  │
┌──────────────────────────────────────────────┐  │
│ [3] Page Fault Handler                       │  │
│ Fault occurs → handler adds page to dirty    │  │
│ list and sets protection to PROT_WRITE.      │  │
└──────────────────────────────┬───────────────┘  │
                               │                  │
                               ▼                  │
┌──────────────────────────────────────────────┐  │
│ [4] Fuzzcase Ends                            │  │
│ Execution completes                          │  │
└──────────────────────────────┬───────────────┘  │
                               │                  │
                               ▼                  │
┌──────────────────────────────────────────────┐  │
│ [5] Snapshot Restore                         │  │
│ Lucid iterates dirty list → memcpy snapshot  │  │
│ contents back into those pages.              ├──┘
│ (No syscalls, all user-space.)               │
└──────────────────────────────────────────────┘
```

### Redqueen for Compare Solving
I also was able to implement Redqueen by instrumenting compare instructions in Bochs. We'll get into Redqueen in more details below when we enable compare coverage in our fuzzing experiment and try to determine how helpful it is for this specific target. 

## Harness Development
With that out of the way, we need something to fuzz! For this, I wanted to do something very broad and shallow, so I homed in on looking at Linux kernel subsystems that accessible via Netlink. Netlink is a network/communication protocol that allows userspace to communicate with the kernel over sockets, vs. something like a driver or a syscall. A lot of the bugs that have been exploited in public the last 5 years ,have been bugs in subsystems that have Netlink plumbing, things like: netfilter, the packet scheduler, etc. Because these subsystems are designed to just receive bytes of Netlink buffer data, I thought this would be a great first thing to get fuzzing on. 

Since we want to fuzz multiple subsystems (broad, shallow), we first have to figure out how Netlink communications normally function. The typical workflow of a userspace program or utility that wants to communicate with the kernel over Netlink is to open a Netlink socket of a specific type of Netlink protocol, something like the following that use in the harness: `NETLINK_ROUTE`, `NETLINK_XFRM`, `NETLINK_NETFILTER`, and `NETLINK_CRYPTO`. For example:

```c
socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)
```

When the userspace program sends data to the Netlink socket that has a protocol associated with it, we end up in [`netlink_sendmsg`](https://elixir.bootlin.com/linux/v6.17/source/net/netlink/af_netlink.c#L1814). This function's job is basically to create an appropriately initialized `struct sk_buff` that wraps the user's data that was sent via the `sendmsg` syscall. This socket buffer is then dispatched to the appropriate handler (in the example, the handler for NETFILTER would be [`nfnetlink_rcv`](https://elixir.bootlin.com/linux/v6.17/source/net/netfilter/nfnetlink.c#L650)). 

So what I want to do is skip any userspace to kernel context switching in our harness and just inject our fuzzing inputs directly into kernel space to be dispatched to the appropriate handlers. So I ended up structuring the fuzzing input as a series of what I'm calling "messages" and each "message" is its own Netlink message for a random protocol that we're fuzzing. I settled arbitrarily on fuzzing inputs maxing out at 16 messages, so we can randomly send any number of messages per input up to 16. In the fuzzing harness, we use these data structures to create a fuzzing input:

```c
// An input structure
struct lf_input {
	u32 total_len;
	u32 num_msgs;
	u8 data[];
};

// A message structure
struct lf_msg {
	u32 protocol;
	u32 msg_len;
	u8 data[];
};
```
So the entire input structure is described by `struct lf_input` which tells us the total length of the messages it contains and the number of messages followed by all of the messages stuffed together. An individual message is described by `struct lf_msg` which contains a `protocol` member corresponding to one of the NETLINK protocols we listed earlier (`NETLINK_ROUTE`, `NETLINK_XFRM`, `NETLINK_NETFILTER`, and `NETLINK_CRYPTO`) and then the message's length `msg_len` and the message's data thereafter.

```text
lf_input {
  total_len: 4 bytes
  num_msgs:  4 bytes
  ────────────────────
  lf_msg {
    protocol: 4 bytes  (ROUTE=0, XFRM=1, NETFILTER=2, CRYPTO=3)
    msg_len:  4 bytes
    data:     variable (netlink message bytes)
  },
  lf_msg {
    protocol: 4 bytes  (ROUTE=0, XFRM=1, NETFILTER=2, CRYPTO=3)
    msg_len:  4 bytes
    data:     variable (netlink message bytes)
  },
  ... (up to 16 messages)
}
```

For testing and development purposes, I leveraged the flexibility/power of snapshot fuzzing to just add a new syscall to the Linux kernel that looked like:
```c
SYSCALL_DEFINE2(lucid_fuzz, const void __user *, data, size_t, len)
{
    printk("Inside lucid fuzz!\n");
	int ret = 0;

	// Initialize everything we need to fuzz
	ret = lf_init(data, len);
	if (ret)
		goto done;

    printk("Initialization done\n");

	// Handle fuzz inputs
	if (lf_handle_input()) {
		ret = -EINVAL;
		goto done;
	}

	// Cleanup resources, not needed when fuzzing, but good for testing
	lf_cleanup();

done:
    printk("Inside done, returning %d!\n", ret);
	return ret;
}
```

So this will take a user supplied data buffer and send it to `lf_init`, which is a function I wrote that pre-allocates the socket buffers we want to use (remember we know that at most we can send 16 messages) and finds all of the Netlink subsystem receive handlers, functions like: `nfnetlink_rcv`, `rtnetlink_rcv`, `crypto_netlink_rcv`, and `xfrm_netlink_rcv`. When not fuzzing under Lucid, the syscall will copy the user supplied data into the global "fuzzcase" variable and then `lf_handle_input` will take care of wrapping that fuzzcase into the appropriate pre-allocated socket buffer and sending it to the appropriate handler. Here is what `lf_handle_input` looks like, this is where the magic happens. Keep in mind that the `fc` variable is a global, standing for "fuzzcase" and this is where Lucid injects fuzzing inputs:
```c
// Main fuzzcase handling logic
int lf_handle_input(void) {
	int i = 0;
	struct lf_input *curr = NULL;
	struct lf_msg *msg = NULL;
	u32 remaining = 0;
	u32 offset = 0;
	struct sk_buff *fuzz_skb = NULL;

	printk("Inside lf_handle_input\n");

	/** LUCID TAKES SNAPSHOT HERE **/
	asm volatile("xchgw %dx, %dx");

	// Make sure we have enough size to make an `lf_input` struct
	if (fc.input_len < sizeof(struct lf_input))
		return 1;

	// Get the `lf_input` and do sanity checks
	curr = (struct lf_input *)fc.input;
	if (curr->total_len != fc.input_len || curr->total_len > LF_MAX_INPUT_SIZE)
		return 1;

	if (curr->num_msgs > LF_MAX_MSGS)
		return 1;

	// Remaining bytes to consume
	remaining = curr->total_len;

	// Since we created a structure, we have consumed the `lf_input` header, we
	// can count those bytes as consumed and update remaining
	remaining -= LF_INPUT_HDR_SIZE;

	// Update offset to point to the first message
	offset = LF_INPUT_HDR_SIZE;

	// Parse and handle the messages in the
	for (i = 0; i < curr->num_msgs; i++) {
		// Make sure we have enough size to make an `lf_msg` struct
		if (remaining < LF_MSG_HDR_SIZE)
			return 1;

		// Create an `lf_msg` struct
		msg = (struct lf_msg *)(fc.input + offset);
		if (msg->msg_len > LF_MAX_MSG_SIZE || msg->protocol >= LF_NUM_PROTOCOLS)
			return 1;

		// We've now consumed the message header bytes
		remaining -= LF_MSG_HDR_SIZE;

		// Make sure we have enough data remaining to fill this message
		if (remaining < msg->msg_len)
			return 1;

		// Create a fuzzcase skb to send to netlink_rcv function
		fuzz_skb = create_fuzz_skb(msg, i);
		if (!fuzz_skb)
			return 1;
		
		// Dispatch the skb to the appropriate handler
		dispatch_skb(msg, fuzz_skb);

		// Update offset
		offset += (LF_MSG_HDR_SIZE + msg->msg_len);

		// Update remaining
		remaining -= msg->msg_len;
	}

	// Check to see if we have remaining, if we do, something is amiss
	if (remaining)
		return 1;

	/** LUCID RESTORES SNAPSHOT HERE **/
	asm volatile("xchgw %bx, %bx");

	// Success
	return 0;
}
```

We iterate through the array of messages, parse them, and send them on their way to the appropriate subsystem. I also made this harness extremely strict so that we fail if anything is amiss, even if we have leftover bytes after parsing. This will cause `lf_input` to return early and not reach the snapshot restoration NOP instruction. This would cause the fuzzcase to "escape" the fuzzing harness and would eventually incur a timeout. In Lucid, we do timeouts based on the number of emulated instructions. So it would be immediately obvious if we had some mutator/generator/harness bug because the fuzzcases would timeout. 

During this portion of development, I was really focused on optimizing the harness. I wanted to skip all of the Netlink sanity checking and plumbing that takes place after the initial `netlink_sendmsg` function thinking this would speed up the fuzzer a substantial amount. I was really careful to retain semantic equivalence to that skipped code though. However, in the end, I made mistakes that you may be able to spot. For instance, during a normal `netlink_sendmsg` call, the socket buffer that it creates doesn't have all of the same fields initialized and it doesn't use kernel sockets. So I actually had a single false positive `NULL` pointer dereference crash at one point during my longest fuzzing session that wouldn't have existed if I had retained 100% semantic equivalence. I think going forward on the blog, I'll move more towards less invasive harnessing and just eat the performance hit. It became apparent when our fuzzcases started reaching deeper code paths that the fuzzer was extremely slow and the aggressive optimization in the harness wouldn't have really made much of a difference, so I'm going to skip that going forward. 

It should be noted that this is not a great approach for *finding bugs*. We're merely trying to assess how Lucid does fuzzing some real code. Sending random messages per input to the various subsystems that have little interplay with one another and can't access each other in any meaningful way is not a strategy for reaching deep code and finding complex bugs. Fuzzing in this way is more likely to reveal simple shallow parsing level bugs, and in 2025 that is probably not going to yield many results. 

## Stage-1 Fuzzing: Dumb Byte Mutator
First thing is first, let's throw some random bytes at these Netlink handlers. To do this, I changed how Lucid sees mutator code. Now, there is a top-level `Mutators` crate and it defines several generic traits and characteristics that every custom mutator implementation must have. These are things like a `rand` function for example. But after you implement the generic stuff that the core fuzzer relies on existing, you are free to have as custom of a mutator as you like. Now you can implement any mutator you want and put it under `mutators/` in the source code directory. This allows some pretty nice flexibility. I added a command line flag to specify a mutator by name and then they are created by the factory type function here in `mod.rs`:
```rust
/// Simple factory to create mutators by name (extend as needed).
pub fn create_mutator(
    name: &str,
    seed: Option<usize>,
    max_size: usize,
) -> Result<Box<dyn Mutator>, LucidErr> {
    match name {
        "toy" => Ok(Box::new(ToyMutator::new(seed, max_size))),
        "netlink" => Ok(Box::new(NetlinkMutator::new(seed, max_size))),
        _ => Err(LucidErr::from(&format!("Unrecognized mutator '{}'", name))),
    }
}
```
I started off by just implementing some basic mutation strategies:
- `ByteInsert`: Randomly insert bytes of arbitrary value into the message buffer
- `ByteOverwrite`: Randomly overwrite a byte in the message with a byte of arbitrary value
- `ByteDelete`: Randomly delete a byte from the message buffer
- `BitFlip`: Randomly flip a bit in the message buffer
- `ProtocolChange`: Randomly change the protocol of a message (ie, switch from `NETLINK_ROUTE` to `NETLINK_NETFILTER`)

In addition to these strategies, the mutator will often "stack" these strategies per input. I defined a `MAX_STACK` of 7 (arbitrary), and so the mutator may choose to randomly mutate the input with up to 7 of these strategies per iteration. 

These mutation strategies actually achieved quite a bit of code coverage surprisingly. Initially, the iterations were extremely short because most Netlink messages we sent were nonsensical. The Netlink message structure looks like this:
```c
/**
 * struct nlmsghdr - fixed format metadata header of Netlink messages
 * @nlmsg_len:   Length of message including header
 * @nlmsg_type:  Message content type
 * @nlmsg_flags: Additional flags
 * @nlmsg_seq:   Sequence number
 * @nlmsg_pid:   Sending process port ID
 */
struct nlmsghdr {
	__u32		nlmsg_len;
	__u16		nlmsg_type;
	__u16		nlmsg_flags;
	__u32		nlmsg_seq;
	__u32		nlmsg_pid;
};
```

Since we're sending random bytes, we rarely have a `nlmsg_len` that makes sense for our random message array of bytes. So it took a while for the fuzzer to generate the right type of input to solve early message parsing to actually reach code behind that sanity check. We had to generate an input that had the right length.

Here are the results I achieved with this simple mutator and our aforementioned harness in a short time:
```text
[lucid stats (start time: 2025-09-19 08:57:11)]
globals: uptime: 0d 22h 26m 28s | fuzzers: 8 | crashes: 0 | timeouts: 0
perf: iters: 88.266M | iters/s: 206.81 | iters/s/f: 25.85
cpu: target: 92.7% | reset: 6.8% | mutator: 0.0% | coverage: 0.5% | redqueen: 0.0% | misc: 0.0%
coverage: edges: 16917 | last find: 0h 2m 6s | map: 25.81%
snapshot: dirty pages: 3841 | dirty / total: 0.00068% | reset memcpys: 438
corpus: inputs: 31000 | corpus size (MB): 318.303 | max input: 0x8088
```

You can see that we fuzzed the harness with this iteration of the mutator for almost a full day on my development VM. It surprisingly captured quite a bit of edges, around ~17k. We can also see that we were able to process quite a bit of iterations as we almost reached 100 million iterations during that time period. Globally across all 8 fuzzers we were sitting at about 200 iterations/sec when the last stats banner printed. Relatively speaking to subsequent versions of the mutator, this is quite a bit of throughput. This is because, like we discussed, most inputs simply didn't pass initial parsing and so they returned early; in other words, our mutator created a ton of junk that didn't do anything worthwhile. So while the throughput looks good on paper, it's actually not good for us. We can also tell this by the relatively high number of CPU time we spend in `reset`, meaning we spend almost 7% of our time performing snapshot resets. 

It should be noted before we get much further comparing results across different iterations of the fuzzer that these results are likely not very meaningful. We can possibly deduce large picture conclusions like: it's better to send inputs that have a sane `nlmsg_len`, but the results are likely too random to glean much else when we aren't making 10x improvements. So keep that in mind, we aren't doing a proper experiment here. I make a change to the fuzzer, run it for a day or so, check results, compare, repeat. With how low our throughput is (Lucid is very slow), and how limited our fuzzing time is, we can't produce high-quality statistics. 

It should also be noted that when I tweeted about fuzzing with Lucid using this mutator, I mentioned that the fuzzer did find an edge case OOB read bug, but it was artificial in that upstream sanity checks that our harness skips would prevent it from happening. So I'm not counting it as Lucid's first 0day. 

## Stage 2 Fuzzing: More Mutation Strategies
The next step is to flesh out the mutator a little more. For the next step, I added several new mutation methods that would enable us to increase our efficiency (not send so much garbage) and also create inputs that would've previously been pretty impossible. 

I added the following mutation strategies: 
- `UniProtocol`: Make every message in the input target the same protocol 
- `DuplicateMessage`: Duplicate one of the messages in the input
- `ShuffleMessages`: Randomly shuffle the order of the messages in the input
- `SpliceMessage`: Steal a message from another input and splice it into the current input
- `PatchHeaderLen`: Determine what the correct `nlmsghdr->nlmsg_len` value should be and patch it
- `PatchHeaderType`: Somewhat intelligently, put message type values in place of `nlmsghdr->nlmsg_type` for the subsystems we're targeting
- `PatchHeaderFlags`: Randomly create somewhat logically sane `nlmsghdr->nlmsg_flags` values

This step helped us quite a bit, it basically improved our efficiency by 2x:
```text
[lucid stats (start time: 2025-09-20 16:24:38)]
globals: uptime: 0d 14h 8m 35s | fuzzers: 8 | crashes: 0 | timeouts: 0
perf: iters: 2.821M | iters/s: 31.18 | iters/s/f: 3.90
cpu: target: 97.4% | reset: 2.4% | mutator: 0.0% | coverage: 0.1% | redqueen: 0.0% | misc: 0.0%
coverage: edges: 17740 | last find: 1h 4m 52s | map: 27.07%
snapshot: dirty pages: 7455 | dirty / total: 0.00132% | reset memcpys: 648
corpus: inputs: 313510 | corpus size (MB): 3779.988 | max input: 0x8088
```

As you can see, we were able to capture more edges in about half the time wall-clock wise. In terms of iterations, we were able to capture more edges in 40x less iterations. So this is a pretty massive efficiency boost. I think most of this comes from having sane `nlmsghdr->nlmsg_len` values being saved to the corpus as well as the mutation strategies that allow us to create more complex inputs. 

Previously if we were able to randomly generate a message that achieved quite a bit of code coverage, we were kind of limited in that we would have had to get extremely lucky to have another message in the same input randomly become similarly successful via dumb byte flipping. Instead now, we have new strategies like message duplication, message splicing, and unifying protocols so that each message has a chance to be sent to the same subsystem etc, and we can achieve deeper code coverage because our messages can now build off of previous messages in the same input. 

Because our inputs had such a dramatically higher chance of passing initial parser checks now, our throughput has plummeted to around 2-4 iterations/sec/fuzzer. I have to admit this was shockingly lower than I expected for the fuzzer. I know Bochs emulation is a considerable slow down from native execution, somewhere around 100x I believe, but I hadn't really seen it yet because up to this point we had only fuzzed toy targets for fuzzer development. This is why people say not to optimize too early, we had no idea that our Bochs emulation bottleneck was so pronounced and we could've spent so much time micro-optimizing core fuzzer code and it wouldn't have made a difference at all. 

## Stage 3: Adding Compare Coverage with Redqueen
To this point, we hadn't been using Lucid's built in Redqueen tooling. For those that are unaware, [Redqueen](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-2_Aschermann_paper.pdf) is the name of a fuzzing paper by the geniuses at Ruhr-University in Bochum that tackles the problem of solving comparisons in fuzzing.

Oftentimes in fuzzing, the target will want to compare values derived from your input to values that it knows should/could exist. For instance, the following may exist semantically in a fuzzing target:
```c
if (*(uint32_t *)(&fuzzing_input[0x1337]) == 0xdeadbeef) {
  buggy_function();
}
```

In this example, the target is checking our input for the presence of a magic value, in this case `0xdeadbeef`. A lof of the time, these simple magic byte value checks represent a huge roadblock in automated fuzzing with no human in the loop. Using our dumb byte flipping mutations, we would have to successively target the 4 consecutive bytes and also randomly make them all the write value. This can be basically impossible in a lot of circumstances. 

Redqueen's contribution is that these types of checks often boil down to `cmp` instructions on x86 architectures, where two "operand values" are compared with one another, these being the left operand and the right operand. Now from the point of view of determining which side is derived from the input and which side is derived from the program, it is often impossible to make this distinction. So what Redqueen does is it searches the input for both operands, if it finds one of the operands, it replaces it in the input with the other operand value, hoping that we can now pass the check. 

This would be extremely expensive normally during fuzzing, so to minimize overhead, Redqueen only performs this type of mutation on inputs that recently found new code coverage, this way the overhead is mostly a one-time cost and the overhead asymptotes to zero as the campaign progresses and new coverage becomes ever more rare. 

This isn't really a fair overview of the technique, but this conveys the gist. Please read the linked paper if you're interested, it's probably my favorite fuzzing paper to date.

We can implement this in our fuzzer because we have access to all compare instructions of all sizes for free in Bochs. So now, what I do is, when I find a new input, I toggle something in the shared execution context data structure between Lucid and Bochs called the "CPU mode" and this tells Bochs what kind of emulation we're doing. Once we find a new input, I replay the input but with the CPU mode set to `Cmplog`. This will cause Bochs to report all of the operand values that it sees in the compare instructions, the instruction pointer value, and the size of the operands back to Lucid. Lucid can now create a data base of values and try the Redqueen strategy for more coverage. 

However, we ran into a huge problem, check out the statistics from the Redqueen enabled run:
```text
[lucid stats (start time: 2025-09-21 20:13:29)]
globals: uptime: 0d 14h 18m 23s | fuzzers: 8 | crashes: 0 | timeouts: 0
perf: iters: 369.79K | iters/s: 0.10 | iters/s/f: 0.01
cpu: target: 9.1% | reset: 0.0% | mutator: 0.0% | coverage: 0.0% | redqueen: 90.9% | misc: 0.0%
coverage: edges: 15829 | last find: 0h 17m 16s | map: 24.15%
snapshot: dirty pages: 7224 | dirty / total: 0.00128% | reset memcpys: 532
corpus: inputs: 32272 | corpus size (MB): 430.671 | max input: 0x8088
```

We basically were only doing Redqueen analysis for the entire fuzzing run of 14 hours wherein we got roughly 7 global iterations through per second. This means that Redqueen has become a prohibitive bottleneck. And we can tell by the amount of edges we discovered that it didn't help much, at least not initially. This general pattern can be expected:
1. Early in the campaign we find new coverage often
2. Inputs are being sent to Redqueen often

That is not surprising. However, I found that there were *several* problems with the Redqueen implementation itself.

The Redqueen paper also pointed out that sometimes input data is *transformed or encoded* before being compared. For instance, maybe input data is originally a `u64` value but is cast as an `i32` before being compared. If that were the case, we would never find the compare operand value for the `i32` in our input, so we would instead need to precompute a handful of common encodings and instead search for them. If we found the compare operand -> encoding value, we'd then replace it with the same encoding of the other operand value. This makes sense. However, I had a logic bug in my implementation that attempted to solve the compare by generating *all possible encodings* for the found operand value instead of the single matching encoding. This increased the number of input patches to try by 15-20x.

The Redqueen paper also discovered that substituting the operand value but doing arithmetic to -1 or +1 the value was helpful in passing less/greater than comparisons. Remember we only hook compare operations that might set CPU flags and we don't know what the program does with that information afterwards so this helps us bypass those checks as well. So in my erroneous implementation, that will 3x the number of patches we attempt which was already 15-20x too many, so that's now around 45-60x too many patches to test.

So here's a concrete example of what I was doing:
1. I receive a report of an operand value pair 0x1337 and 0xdead. These are 2 byte values. 
2. I was pre-computing every possible encoding for both pairs (this part is correct)
3. If I found an encoding variant of 0x1337, say zero-extended to a `u32`, so 0x00001337 in the input, what I should be doing is applying that same encoding scheme to its partner value and creating 0x0000dead. Then I would replace 0x00001337 in the input with 0x0000dead.
4. Instead, I was replacing 0x00001337 with *every possible similarly sized encoding of 0xdead*

But wait, it gets worse! I was also not deduplicating operands based on the `RIP` value of the `cmp` instruction. Now normally, this can be ok because it allows you to potentially pass more dynamic comparisons where maybe both operand values are everchanging based on your input, say a checksum for example. However, with our throughput issues, and just wanting to do the bare-minimum here and defeat classic magic number comparisons, we can whittle down the number of input patches to try significantly by ignoring operands collected from `RIP` values we've already collected. We will rely on human-in-the-loop intervention if we ever need to defeat checksum type comparisons. 

To cap everything off, I was *creating all of the patched inputs* before trying them all serially. So I would pre-compute the patched inputs and stuff them in an input queue that Lucid would then prioritize over normal mutations. This led to my fuzzers being `SIGKILL` by the kernel as they started holding too many inputs in memory overnight. That is actually what ended this stage of experimentation. So this fuzzing stage was an abject disaster and we end up making a ton of improvement in the next iteration. 

*Minor Note*: The Redqueen paper also employed a technique it called "colorization" wherein the input would be "colored" with random bytes up until the coloring changed the execution path of the input. So it would overwrite input data with random bytes and check to see if that affected the execution path. It started with the largest amount of randomization possible and then using something like binary search, would continue to shrink the portions of the input that would be colorized until its execution trace matched the original. The purpose of this is to make finding operand values in the input easier. Instead of an input being full of 0x0 values for instance, it now contains random data and when you capture the compare operand values, that random data in the capture is easier to spot in the input and you don't run the risk of duplicating candidate insertions. This is actually genius. Lucid has this feature too, but I found that I was spending **dozens of seconds** colorizing large inputs. This is because we simply are so slow. I decided that the juice wasn't the squeeze and made it such that in order to use colorization now, you have to pass a command line flag to opt into it. 

## Stage 4: Fixing Redqueen
Besides fixing the aforementioned logical errors, I added some new logic to the implementation. First, I started deduping operand values collected by the `RIP` value. So we no longer are doing Redqueen analysis for the same `RIP` compare operands more than once. 

Additionally, I stopped collecting compare operands for values that weren't at least 4 bytes in size. I figure that most mutators should be able to randomly pass 1 and 2-byte comparisons by sheer luck. 

I also capped the number of Redqueen inputs you can put in the fuzzer's test queue at 500. In my testing, we never even really approached 500 inputs in the test queue with the fixed encoding search, deduping `RIP`, and removing < 32-byte compares. Previously, in the broken impelmentation, some fuzzers were carrying up to 1 million inputs to test!

Fixing the bugs and adding these two new things to the Redqueen code helped immensely and we achieved the following fuzzing run:
```text
[lucid stats (start time: 2025-09-22 11:47:27)]
globals: uptime: 0d 5h 49m 26s | fuzzers: 8 | crashes: 0 | timeouts: 0
perf: iters: 738.01K | iters/s: 34.30 | iters/s/f: 4.29
cpu: target: 98.1% | reset: 1.8% | mutator: 0.0% | coverage: 0.1% | redqueen: 0.0% | misc: 0.0%
coverage: edges: 16100 | last find: 0h 1m 10s | map: 24.57%
snapshot: dirty pages: 7290 | dirty / total: 0.00129% | reset memcpys: 557
corpus: inputs: 70366 | corpus size (MB): 877.591 | max input: 0x8088
```

As you can see, we doubled the throughput in half of the wall-clock time. We also didn't use so much memory that the fuzzers got killed, so that's good. Now that Redqueen is fixed, we can move on. 

### Redqueen Success Example
Redqueen proved to be extremely helpful at finding new edges once we got away from the first 30 minutes or so of fuzzing. This was an awesome example I have to share:
```text
[lucid stats (start time: 2025-09-24 15:23:35)]
globals: uptime: 0d 0h 56m 54s | fuzzers: 8 | crashes: 0 | timeouts: 0
perf: iters: 96.08K | iters/s: 18.05 | iters/s/f: 2.26
cpu: target: 97.7% | reset: 1.4% | mutator: 0.0% | coverage: 0.0% | redqueen: 0.7% | misc: 0.0%
coverage: edges: 19920 | last find: 0h 0m 56s | map: 30.40%
snapshot: dirty pages: 8122 | dirty / total: 0.00144% | reset memcpys: 982
corpus: inputs: 2581 | corpus size (MB): 8.827 | max input: 0x10088
fuzzer-2: Fuzzing increased edge count 19475 -> 19476 (+1)
fuzzer-1: Fuzzing increased edge count 19505 -> 19507 (+2)
fuzzer-7: Fuzzing increased edge count 19194 -> 19196 (+2)
fuzzer-4: Fuzzing increased edge count 19365 -> 19370 (+5)
fuzzer-4: Redqueen increased edge count 19370 -> 19721 (+351)
fuzzer-4: Redqueen increased edge count 19721 -> 19784 (+63)
fuzzer-4: Redqueen increased edge count 19784 -> 20925 (+1141)
```
`fuzzer-4` starts off well behind the record edge count (`19920`) at `19365` edges discovered. It uses normal fuzzing mutation strategies and increases its edge count to `19370`. Then, that new-edge-finding input is sent to Redqueen for processing and Redqueen *dramatically* increases the fuzzer's edge discovery progress. It rapidly discovers `1555` new edges which is an 8% increase over what it had just reached with fuzzing.

## Stage 5: Adding Seeds, Mutator Tweaks, Misc.
### Seeds
In this stage, the focus was mainly on creating seed inputs that would start the fuzzing campaign off with a lot of coverage. Up to this point, the most edges we ever discovered for this fuzzing target/harness was around 17.5k which we saw with our improved mutator but without compare coverage and running for around 14 hours. Now, that doesn't mean that compare coverage is a hinderence to edge discovery, it just means that early on it's not as effective at finding new edges as the normal fuzzing strategies were. With seeds, I was hoping to see a dramatic increase in the number of edges discovered because we'd be spoon feeding the mutator some of the complex inputs it needs to generate. 

To create seed inputs, I actually just created an `LD_PRELOAD` shared object that hijacked the `sendmsg` libc invocation found in several command line utilities that normally come packaged in Ubuntu to interact with these subystems. I'm talking about `tc` for setting up qdiscs or the network scheduler for `NETLINK_ROUTE`, or `nft` to interact with `nf_tables` for `NETLINK_NETFILTER` etc. I simply hook the `sendmsg` libc function and have it dump the message contents to the terminal in hex. Here is an example:
```text
root@luciddev:/home/h0mbre/netlink_fuzzing# LD_PRELOAD=./hexdump_netlink.so tc qdisc add dev dummy0 root pfifo_fast
echo "3400000024000506fa2cd46800000000000000000700000000000000ffffffff000000000f000100706669666f5f666173740000"
```
Then I just pasted that `echo` string into the terminal and wrote the hex to a file and then wrapped those bytes in our fuzzing input data structure using Python:
```python
#!/usr/bin/env python3
import sys

# lf_protocols = {0: ROUTE, 1: XFRM, 2: NETFILTER, 3: CRYPTO}

def build_seed(hex_string: str, protocol: int, out_file: str):
    # Parse hex string into bytes
    payload = bytes.fromhex(hex_string)
    payload_len = len(payload)

    # Lengths
    lf_msg_hdr_len = 8
    lf_input_hdr_len = 8
    total_len = payload_len + lf_msg_hdr_len + lf_input_hdr_len
    num_msgs = 1

    # Build buffer
    buf  = total_len.to_bytes(4, "little")
    buf += num_msgs.to_bytes(4, "little")
    buf += protocol.to_bytes(4, "little")
    buf += payload_len.to_bytes(4, "little")
    buf += payload

    # Write to disk
    with open(out_file, "wb") as f:
        f.write(buf)

    print(f"Wrote {out_file} ({len(buf)} bytes, payload={payload_len} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <hex_string_file> <protocol_idx> <out_file>")
        sys.exit(1)

    hex_file, protocol_str, out_file = sys.argv[1:]
    protocol = int(protocol_str)

    with open(hex_file, "r") as f:
        # join lines, strip whitespace/newlines
        hex_string = "".join(line.strip() for line in f)

    build_seed(hex_string, protocol, out_file)
```

I think all in all I created ~30 seeds this way. I seeded each target protocol with at least 1 seed besides `NETLINK_CRYPTO`. The vast majority of the seeds became single message inputs and were simple in nature. For `nf_tables` specifically, I did create one input that was a series of messages to do stateful things like:
create a table, then create a set, then create an object, etc. 

When fuzzing with seeds, our coverage increased dramatically. The seeds alone found over 17k edges. The lesson learned is nothing new, but having good seeds **dramatically** enhances your fuzzing efficiency. 

### Mutator Tweaks
Since we're so limited on throughput, I really wanted to make sure the inputs we were creating weren't wasting cycles. On average we were spending over 98% of our CPU time executing the target and spending roughly 2% of the time doing snapshot resets. At that much target time, it's clear where the bottleneck is and it's not on anything the fuzzer itself is doing. 

This kind of frees up to do more things in the fuzzer since it won't slow the process down at all really. So what I decided to do was start hashing every input that the mutator created and comparing it to a database of the last `n` inputs, which I set arbitrarily at `500_000`. So now, every input we create is guaranteed to not be a repeat of the last 500k inputs. This helps a little when it comes to throughput because we're not wasting precious CPU time re-running an often seen input. 

I also made sure that when the mutator was choosing mutation strategies that it would no longer accept a NOP operation in place of an applied mutation. As an example, say we get an input from the corpus to mutate and that input is already the maximum size. Previously, if we were to randomly select the `ByteInsert` mutation method for this input it would effectively perform a NOP and return without doing anything. This is potentially a waste of input creation cycles. So I changed the function signature of the mutation strategies to return a `bool` where `true` meant the mutation was successfully applied and `false` meant that it was not. This way we can make sure at least *some* mutation is applied to each and every input. 

Lastly, I keep a constant defined in the netlink mutator that is supposed to represent the percentage of inputs that we generate from scratch. It had previously been set at 5% and I lowered it to 1% now that we have seeds. I figured this would stop us from sending so much garbage while still allowing us to do something very random that still reaches some never before reached error handling paths. In addition to the rate change, I also refactored the random generation function to produce Netlink message-like inputs instead of random blobs of data of varying lengths. Now when we generate messages from scratch, they are at least shaped like valid Netlink messages. 

### Misc
#### Hitcount Change
Some of the previous runs had absolutely exploded the corpus size, for instance in Stage 2 we had accumulated over 300k inputs in the corpus. I wanted to try and cut down on this bloat where possible because my intuition was that we were saving too many inputs. By default, Lucid would save an input if it discovered what it considered a new edge pair, eg a new basic block transition and it would save an input if it reached an edge pair a record number of times, called a hitcount. I bucket the hitcounts like AFL++ does:
```rust
/// After a fuzzing iteration, Bochs will have updated the curr_map with
    /// hit counts for each edge pair that was reached during that fuzzing
    /// iteration. Instead of keeping the hit counts literal, we instead "bucket"
    /// the hit counts into categories. So for instance if we hit an edge pair
    /// 19 times, it will be placed in the 32 hitcount bucket. This algorithm
    /// is stolen directly from AFL++ who obviously has a ton of empirical
    /// evidence showing that this is beneficial
    #[inline(always)]
    fn bucket(hitcount: u8) -> u8 {
        match hitcount {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            128..=255 => 128,
        }
    }
```

So, if we move from a hitcount record on an edge pair of 4 and an input achieves a hitcount of 5, we don't save it. But if the second input were to achieve a hitcount of 8, placing it in a new bucket, it would get saved. The ratio of these hitcount record setting inputs to edge pair discovery inputs was easily more than 10 to 1 and I felt like, especially early in the campaign, they were kind of just noise and not extremely helpful. 

What I moved to was a model where I only considered new hitcount records if we were "starved" for new coverage. I created the command line option to set a "starved" for coverage threshold in wall-clock time, so once you reach that, the fuzzer starts saving hitcount record inputs to the corpus. During our longest fuzzing iteration, we reached the starved state of an hour multiple times and it seemed beneficial to the fuzzing campaign at that point to save these types of inputs as they soon after found new coverage. 

#### Corpus Sampling
In another effort to avoid corpus bloat, I moved from a model where every fuzzer gets every other fuzzer's entire corpus every sync-interval (tunable at runtime via command line), every fuzzer would instead ranomdly sample inputs from other fuzzers for the entirety of the sync-interval before it would put them all back on disk and randomly pick more to sample. For my longest campaign I set this sync interval to 1 hour. 

#### Corpus Biasing
Lastly, I decided to play with how the corpus would provide inputs to the mutator. I implemented a couple of methods: `get_input_uniform` and `get_input_bias_new`. The former would just randomly select an input from the corpus with uniform distribution (including the sampled inputs) and the latter would bias the newer inputs in the corpus by a tunable rate. For my longest campaign I made it to where around 67% of the time, we'd pick a new input. Sampled inputs from other fuzzers were considered "new" as well in this due to the way I implemented the sampling. I have to say, I don't think this made a bit of difference in our progress. I think in a long enough time horizon it probably doesnt matter much. 

We ended up setting a substantial edge-finding record in just 15h of wall-clock time and under 2 million iterations. 
```text
[lucid stats (start time: 2025-09-25 21:22:08)]
globals: uptime: 0d 15h 47m 18s | fuzzers: 8 | crashes: 0 | timeouts: 0
perf: iters: 1.923M | iters/s: 27.05 | iters/s/f: 3.38
cpu: target: 97.7% | reset: 2.2% | mutator: 0.0% | coverage: 0.1% | redqueen: 0.0% | misc: 0.0%
coverage: edges: 25866 | last find: 0h 4m 5s | map: 39.47%
snapshot: dirty pages: 9536 | dirty / total: 0.00169% | reset memcpys: 1475
corpus: inputs: 15689 | corpus size (MB): 44.976 | max input: 0x10088
```

So with all of the improvements over time we were able to go from 17k edges in 90 million iterations to 26k edges in 2 million iterations. I think the biggest positive change was probably just using seeds. I don't think much of the core fuzzer tweaking (reducing corpus bloat, sampling inputs, avoiding hitcount inputs) made too much of a difference.

## Conclusions
### In General
- New snapshot method worked well and continued to be performant deep into campaign with thousands of dirty pages to reset
- Bochs emulation is the main bottleneck in the fuzzer, you probably need quite a bit of hardware to reach coverage saturation for complex targets
- Redqueen provided some huge boosts in edge discovery, but it needs a longer campaign to be beneficial
- Corpus bloat reduction didn't massively affect the fuzzer, at least on our 4 day campaign, it seems benign enough to keep
- Biasing towards newer inputs didn't seem to help the fuzzer find edges more efficiently
- Re-architecting mutators to be plug and play was as huge improvement, now creating a fuzzer is as easy as implementing a custom Mutator
- High-quality seeds are the easiest way to massively boost efficiency

### Per Stage
- Stage 1: High iteration count (88M) but only 16,917 edges - inefficient due to malformed, easily rejected inputs
- Stage 2: Dramatic efficiency gain - 17,740 edges in only 2.8M iterations (~35x more efficient)
- Stage 3: Broken Redqueen severely hurt performance - only 370K iterations in 14 hours
- Stage 4: Fixed Redqueen restored throughput, rare but massive edge discovery gains
- Stage 5: Seeds + optimizations achieved best results - 25,866 edges in 1.9M iterations

### Caveats
- Fuzzing is extremely random, none of these results should be taken at face value besides massive 2-10x improvements
- Fuzzing is highly target dependent. Biasing towards new inputs, our corpus sampling interval, ignoring hit-counts, and reducing corpus bloat didn't seem to have a massive negative effect with this specific target, but may be massively beneficial or harmful against others
- Ideally I would've created line graphs documenting coverage for each stage, but I didn't have the presence of mind to do that, I apologize

## What's Next?
