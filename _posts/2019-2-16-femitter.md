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
  - hackthebox.eu
---

After watching [Ippsec's walkthrough for Dropzone](https://www.youtube.com/watch?v=QzP5nUEhZeg&t=1743s) on [hackthebox.eu](https://hackthebox.eu), I was pretty amazed that you could get code execution on Windows XP with just write privileges. If you have not seen the walkthrough yet, I highly encourage you watch it. He goes over MOF files, Stuxnet, MSF's interactive Ruby shell, etc. 

In the walkthrough, he uses TFTP to upload an executable to the victim's System32 directory and then uploads a malicious MOF file to the System32/wbem/mof directory which runs the executable. I had to try this for myself! I started thinking about potential XP lab setups and settled on Femitter FTP as it allows for directory transversal. Typically, this vulnerability is used for enumeration and file reading, but if there was a way to use the directory transversal to write to directories of interest, we could potentially replicate what Ippsec had done on Dropzone. 


