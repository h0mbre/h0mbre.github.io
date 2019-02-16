---
layout: single
title: Exploiting Femitter FTP in a Post-Dropzone World
date: 2019-2-16
classes: wide
header:
  teaser: /assets/images/Femitter/fem.png
tags:
  - Femitter
  - Directory Transversal
  - DropZone
  - MOF
  - FTP
  - Windows XP
  - RCE
---

After watching [Ippsec's walkthrough for Dropzone](https://www.youtube.com/watch?v=QzP5nUEhZeg&t=1743s) on Hack The Box, I was pretty amazed that you could get code execution on Windows XP with just write privileges. If you have not seen the walkthrough yet, I highly encourage you watch it. He goes over MOF files, Stuxnet, MSF's interactive Ruby shell, etc. 

In the walkthrough, he uses TFTP to upload an executable to the victim's System32 directory and then 
