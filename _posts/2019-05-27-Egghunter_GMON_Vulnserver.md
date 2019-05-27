---
layout: single
title: CTP/OSCE Prep -- 'GMON' Egghunter Exploit in Vulnserver
date: 2019-5-27
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
  - egghunter
  - SEH
--- 
![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## Introduction

This series of posts will focus on the concepts I'm learning/practicing in preparation for [CTP/OSCE](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/). In this series of posts, I plan on exploring:
+ fuzzing,
+ vanilla EIP overwrite,
+ SEH overwrite, and
+ egghunters.

Writing these entries will force me to become intimately familiar with these topics, and hopefully you can get something out of them as well! 

In this particular post, we will become acquainted with an SEH-based overflow with the `GMON` command/parameter in Vulnserver. 

If you have not already done so, please read the first post of this series so that you can setup your environment, setup and use `boofuzz`, and become acquainted with some of the stack-based overflow concepts that are still relevant in this post. You can do so [here](https://h0mbre.github.io/Boofuzz_to_EIP_Overwrite/).

**This post will assume the reader is already familiar with how to attach processes in Immunity, use boofuzz, search for bad characters, and other knowledge domains covered in the first post of the series.**

## Background

If you have not done so, it's probably best that you read our first approach to exploiting the 'GMON' command in Vulnserver with an SEH_based exploit [here](https://h0mbre.github.io/SEH_Based_Exploit/#): 

## Big Thanks

To everyone who has published free intro-level 32 bit exploit dev material, I'm super appreciative. Truly mean it. 

## Resources

+ [Corelan SEH](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
+ [Infosec Institute SEH tutorial](https://resources.infosecinstitute.com/seh-exploit/#gref)
+ [sh3llc0d3r's GMON SEH Overwrite Walkthrough](http://sh3llc0d3r.com/vulnserver-gmon-command-seh-based-overflow-exploit/)
+ [Doylersec's LTER SEH Overwrite Walkthrough](https://www.doyler.net/security-not-included/vulnserver-lter-seh)
+ [Capt Meelo's GMON SEH Overwrite Walkthrough](https://captmeelo.com/exploitdev/osceprep/2018/06/30/vulnserver-gmon.html)
+ [Muts' 2004 Exploit](https://www.exploit-db.com/exploits/1378)
+ [Wallpaper](http://i.imgur.com/Mr9pvq9.jpg)
+ [Dimitrios Kalemis Wonderful Blogpost](https://dkalemis.wordpress.com/2010/10/27/the-need-for-a-pop-pop-ret-instruction-sequence/)
+ [Tulpa OSCE Guide](https://tulpa-security.com/2017/07/18/288/)
