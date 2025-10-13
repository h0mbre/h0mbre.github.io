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
  - Netlink
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
