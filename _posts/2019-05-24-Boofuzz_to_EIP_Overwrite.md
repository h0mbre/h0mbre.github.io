---
layout: single
title: Boofuzz to EIP Overwrite
date: 2019-5-24
classes: wide
header:
  teaser: /assets/images/CTP/1920x1080_Wallpaper.jpg
tags:
  - buffer overflow
  - Windows
  - x86
  - shellcoding
  - exploit development
  - assembly
  - python
--- 
![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## Introduction

While I'm preparing for CTP/OSCE, I thought I'd start blogging what I'm doing so that later on I can use this blog as a reference. In this series of posts, I plan on exploring:
+ fuzzing,
+ vanilla EIP overwrite,
+ SEH overwrite, and
+ egghunters.

Writing these entries will force me to become intimately familiar with these topics and hopefully you can get something out of them as well! 

## Boofuzz to EIP Overwrite

In this particular post, we will become acquainted with the `boofuzz` fuzzer and use it to discover an EIP overwrite vulnerability in Vulnserver. 
