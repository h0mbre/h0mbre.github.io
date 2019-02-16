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

  In the walkthrough, he uses TFTP to upload an executable to the victim's System32 directory and then uploads a malicious MOF file to the System32/wbem/mof directory which runs the executable. I had to try this for myself! I started thinking about potential XP lab setups and settled on Femitter FTP as it allows for directory transversal. Typically, this vulnerability is used for enumeration and file reading, but if there was a way to use the directory transversal to write to directories of interest, we could potentially replicate what Ippsec had done on Dropzone and get code execution. 

### Getting Femitter FTP Up and Running
  The Femitter installer can be downloaded [here](http://acritum.com/fem) and about half-way down the page there is a link to 'Download the latest version.' Once placed on your XP VM, simply run the installer with all default configurations and it will place a folder called 'Femitter' in your 'Program Files' directory. Navigate to the Femitter folder and run the exe. Click on the 'FTP Server' tab and select 'Start.' Check that your VM is now running the FTP server on port 21 with a simple nmap scan.
  
### Quest for RCE
  By default, Femitter will allow anonymous authentication and will drop an authenticated user into the C:/Program Files/Femitter/Shared directory which is not writable. After changing to the 'Upload' directory, which is writable we are able to place files onto the remote box. Let's first test the well-documented directory transversal vulnerability which can be found on Exploit DB [here](https://www.exploit-db.com/exploits/15445). 

![](/assets/images/Femitter/fem_dirTransverse.png)

  Ok awesome, the exploit from nearly 10 years ago still works, this is ground breaking stuff here ;). After trying a bunch of different ways to directly upload files to directories of interest, I was only able to find 2 ways with the Linux FTP client. The first stipulation I found was that your working directory on the FTP server has to be writable. You cannot, for instance put a file and specify a destination path like `../../../../windows/system32/example.exe` without first making sure the working directory is writable. As long as the CWD is writable there are at least a couple of ways to get the files where we want them. The first way is to PUT the file and then specify the destination path like I already said.

![](/assets/images/Femitter/putSystem32.png)
