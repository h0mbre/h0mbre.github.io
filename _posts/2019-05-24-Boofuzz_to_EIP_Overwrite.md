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

This series of posts will focus on the concepts I'm learning/practicing in preparation for [CTP/OSCE](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/). In this series of posts, I plan on exploring:
+ fuzzing,
+ vanilla EIP overwrite,
+ SEH overwrite, and
+ egghunters.

Writing these entries will force me to become intimately familiar with these topics, and hopefully you can get something out of them as well! 

In this particular post, we will become acquainted with the `boofuzz` fuzzer and use it to discover an EIP overwrite vulnerability in Vulnserver. 

## Preparing Our Environment

For this excercise we will need to procure:
+ Windows 7 VM,
+ boofuzz,
+ vulnserver, 
+ Immunity Debugger,
+ Mona, and
+ a remote attacker box (I'll be using Kali).

### Windows 7 VM
For my lab setup, I downloaded an x86 Windows 7 image for Virtualbox [directly from Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) and took a snapshot so that in 90 days, if I still want the VM I won't have to start the process of installing and configuring it from scratch! 

I found that when I downloaded and booted the 'VMware x86' images, they were in fact 64-bit, so beware of that possibility. 

### Boofuzz
Next we will need to install `boofuzz` on our attacker box. If you are on a Debian-based Linux machine, you can run the following commands (if you do not have `pip` installed, first run `apt-get install python-pip`):
1. `git clone https://github.com/jtpereyda/boofuzz`
2. `cd boofuzz`
3. `pip install .`

You can read more about `boofuzz` installation and documentation [here](https://boofuzz.readthedocs.io/en/latest/user/install.html).

### Vulnserver
Now we need our badly written application. I downloaded and used the `.zip` hosted [here](http://sites.google.com/site/lupingreycorner/vulnserver.zip) from my Windows 7 VM, but feel free to download directly from the autor [here](https://github.com/stephenbradshaw/vulnserver). 

The `.exe` will run as long as its companion `essfunc.dll` file is in the same location. I moved both to my desktop for ease of use in the Windows 7 VM. 

### Immunity Debugger
Next we will download our debugger which we will use to investigate how vulnserver is behaving under different circumstances. Access the [download link](https://debugger.immunityinc.com/ID_register.py) from your Windows 7 VM, and fill out the requisite information (I believe dummy data will suffice.) Once you start the installer, it will notice that you do not have Python installed and offer to install it for you. 

### Mona
Mona is a very robust Python tool that can be used inside Immunity to perform a broad range of analysis for us. To install Mona, I just visited the [Corelan Mona repo](https://github.com/corelan/mona/blob/master/mona.py) and copied the raw text to a txt document inside my Windows 7 VM and saved it as `mona.py`. 

We want `mona.py` to be saved in the following directory: `C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands`. 

## Exploring Vulnserver
The first thing we want to do is run vulnserver.exe and then interact with the application as a normal client to determine how the application works under normal circumstances. We don't need to run the process in Immunity just yet. Start the application and you should recieve the following Windows prompt:
![](/assets/images/CTP/vulnserver.jpg)

## Using Boofuzz
Working off of a very detailed and helpful working aid from [zeroaptitude.com](https://zeroaptitude.com/zerodetail/fuzzing-with-boofuzz/), we learn that the first element of any `boofuzz` fuzzing script is the 'session.' We can create our basic 




