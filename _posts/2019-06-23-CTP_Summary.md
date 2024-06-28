---
layout: post
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

Hopefully this series is helpful to a CTP/OSCE student some day! It's now exam-prep crunch time so I will be relatively quiet. Looking forward to posting a review for the course after I'm finished and continuing down the exploit dev path for the forseeable future. Thanks for reading along! 

## Concepts
### SEH Overwrite Resources
+ [My First SEH Overwrite](https://h0mbre.github.io/SEH_Based_Exploit/#)
+ [Corelan SEH Materials](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
+ [Infosec Institute SEH tutorial](https://resources.infosecinstitute.com/seh-exploit/#gref)
+ [sh3llc0d3r's GMON SEH Overwrite Walkthrough](http://sh3llc0d3r.com/vulnserver-gmon-command-seh-based-overflow-exploit/)
+ [Doylersec's LTER SEH Overwrite Walkthrough](https://www.doyler.net/security-not-included/vulnserver-lter-seh)
+ [Capt Meelo's GMON SEH Overwrite Walkthrough](https://captmeelo.com/exploitdev/osceprep/2018/06/30/vulnserver-gmon.html)
+ [Muts' 2004 Exploit](https://www.exploit-db.com/exploits/1378)
+ [Dimitrios Kalemis POP POP RET Explainer](https://dkalemis.wordpress.com/2010/10/27/the-need-for-a-pop-pop-ret-instruction-sequence/)

### Egghunter Resources
+ [My SLAE Egghunter Assignment](https://h0mbre.github.io/SLAE_Egg_Hunter/#)
+ [Skape's Egghunter Explainer](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)
+ [Fuzzy Security Egghunter Tutorial](https://www.fuzzysecurity.com/tutorials/expDev/4.html)
+ [Corelan Win32 Egghunting Guide](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)
+ [Vulnserver: GMON Egghunter with Char Restrictions](https://h0mbre.github.io/Badchars_Egghunter_SEH_Exploit/)

### Fuzzing Resources
+ [ZeroAptitude Intro to Boofuzz](https://zeroaptitude.com/zerodetail/fuzzing-with-boofuzz/)
+ [Boofuzz](https://github.com/jtpereyda/boofuzz)
+ [Boo-Gen](https://github.com/h0mbre/CTP/tree/master/Boo-Gen)
+ [Vulnserver: Boofuzz to TRUN EIP Overwrite](https://h0mbre.github.io/Boofuzz_to_EIP_Overwrite/#)
+ [Using Boo-Gen to Fuzz Xitami Webserver](https://h0mbre.github.io/Xitami_Webserver_SEH/#)

### Alphanumeric Encoding Resources
+ [Vulnserver: A Noob's Approach to Alphanumeric Shellcode (LTER)](https://github.com/h0mbre/h0mbre.github.io/blob/master/_posts/2019-06-01-LTER_SEH_Success.md)
+ [Vulnserver: Alphanumeric Shellcode Exploit for LTER v2.0](https://h0mbre.github.io/LTER_SEH_Overwrite_2/)
+ [OffSec Alphanumeric Shellcode](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/)
+ [Doyler LTER SEH Overwrite Part 1](https://www.doyler.net/security-not-included/lter-seh-continued)
+ [Doyler LTER SEH Overwrite Part 2](https://www.doyler.net/security-not-included/lter-seh-continued)
+ [VelloSec Carving Shellcode](http://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/)
+ [Slink by @ihack4falafel](https://github.com/ihack4falafel/Slink)
+ [Z3ncoder](https://github.com/marcosValle/z3ncoder)

### Hex Encoded Characters
+ [Vulnserver: HTER EIP Overwrite with Hex Encoded Payload](https://h0mbre.github.io/HTER_EIP_Twist/#)

### Net Jumping
+ [OJ Reeves Net Jumping Tutorial](https://buffered.io/posts/jumping-with-bad-chars/)
+ [JMP Opcode Explainer by Unixwiz](http://www.unixwiz.net/techtips/x86-jumps.html)

### Partial Overwrites/Application Memory
+ [Xitami Webserver 2.5](https://h0mbre.github.io/Xitami_Webserver_SEH/)

### Backdooring PEs/Bypassing AV
+ [Backdooring PE File by Adding New Section Header by Capt Meelo](https://captmeelo.com/exploitdev/osceprep/2018/07/16/backdoor101-part1.html)
+ [Backdooring PE File w/ User Interaction & Custom Encoder Using Existing Code Cave by Capt Meelo](https://captmeelo.com/exploitdev/osceprep/2018/07/21/backdoor101-part2.html)

### Socket Reuse
+ [Vulnserver KSTET Exploit by Rastating](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/)
+ [Vulnserver KSTET Exploit by Deceptive Security](https://deceiveyour.team/2018/10/15/vulnserver-kstet-ws2_32-recv-function-re-use/)

## ExploitDB Recreations
+ [Easy File Sharing Web Server 7.2](https://h0mbre.github.io/Easy_File_Sharing_Web_Server/)
+ [Xitami Webserver 2.5](https://h0mbre.github.io/Xitami_Webserver_SEH/)

## Tools/Scripts/Misc
### Exploit Skeletons
+ [Exploit Skeleton Repo by HanseSecure](https://github.com/HanseSecure/ExploitDev/tree/master/poc)

### Tools
+ [Offset Helper Script](https://github.com/h0mbre/CTP/tree/master/Offset)
+ [Boo-Gen (Boofuzz Script Generator)](https://github.com/h0mbre/CTP/tree/master/Boo-Gen)
+ [Slink Add/Sub Encoder for Alphanumeric Shellcode](https://github.com/ihack4falafel/Slink)
+ [Z3ncoder Sub Encoder for Alphanumeric Shellcode](https://github.com/marcosValle/z3ncoder)

### Vulnserver
+ [Vulnserver](https://github.com/stephenbradshaw/vulnserver)

### Prep Guides
+ [Tulpa's OSCE Prep Guide](https://tulpa-security.com/2017/07/18/288/)
+ [Abatchy's OSCE Study Guide](https://www.abatchy.com/2017/03/osce-study-plan)

## Thanks!!!

Huge thanks to everyone who published/publishes all of this amazing free content on entry-level exploit dev topics. I would be lost without all of your hard work. I truly appreciate it!
