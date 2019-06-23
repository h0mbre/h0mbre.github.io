---
layout: single
title: CTP/OSCE Prep -- Wrapping Up Our Prep 
date: 2019-6-23
classes: wide
header:
  teaser: /assets/images/CTP/immunity.jpg
tags:
  - buffer overflow
  - Windows
  - x86
  - shellcoding
  - exploit development
  - assembly
  - python
  - OSCE
  - CTP
  - ExploitDB
  - egghunter
--- 
![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## CTP/OSCE Prep Conclusion

At this point we have touched on all of the topics I wanted to cover before my exam. We covered:
+ alphanumeric shellcoding,
+ egghunters,
+ SEH overwrites,
+ partial overwrites,
+ stuffing shellcode into memory separate from crash payload, and
+ fuzzing.

For completeness, I'm going to include all of the references I found useful and also some resources for some topics we didn't cover such as:
+ backdooring PEs,
+ bypassing AV, and
+ socket reuse. 

### SEH Overwrite Resources
+ [My first SEH overwrite](https://h0mbre.github.io/SEH_Based_Exploit/#)
+ [Corelan SEH Materials](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
+ [Infosec Institute SEH tutorial](https://resources.infosecinstitute.com/seh-exploit/#gref)
+ [sh3llc0d3r's GMON SEH Overwrite Walkthrough](http://sh3llc0d3r.com/vulnserver-gmon-command-seh-based-overflow-exploit/)
+ [Doylersec's LTER SEH Overwrite Walkthrough](https://www.doyler.net/security-not-included/vulnserver-lter-seh)
+ [Capt Meelo's GMON SEH Overwrite Walkthrough](https://captmeelo.com/exploitdev/osceprep/2018/06/30/vulnserver-gmon.html)
+ [Muts' 2004 Exploit](https://www.exploit-db.com/exploits/1378)
+ [Dimitrios Kalemis POP POP RET Explainer](https://dkalemis.wordpress.com/2010/10/27/the-need-for-a-pop-pop-ret-instruction-sequence/)

## Resources

+ [First SEH Overflow](https://h0mbre.github.io/SEH_Based_Exploit/#)
+ [Xitami Download](https://imatix-legacy.github.io/xitami.com/)
+ [Boo-Gen](https://github.com/h0mbre/CTP/tree/master/Boo-Gen)
+ [Offset.py](https://github.com/h0mbre/CTP/tree/master/Offset)
