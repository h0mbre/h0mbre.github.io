---
layout: post
title: Making Gnome Terminal Look Like XTerm 
date: 2019-11-18
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - fonts
  - xterm
---

**DISCLAIMER: I spent about 2 hours of pasting stuff from Stack Overflow into my terminal before this, so if this doesn't work for you, I'm sorry.**

## Turning Back the Font Clock on Gnome Terminal
I, for some unknown reason, am obsessed with the default font for XTerm on Kali Linux. I really really struggled to piece this puzzle together as a \*nix noob, so I'm going to save someone out there the time. 

### Default XTerm Font
The default font in XTerm, at least on my Kali distro, is known as `-misc-fixed-medium-r-semicondensed--13-120-75-75-c-60-iso8859-1`. Now, what the hell does that mean? I have no idea, all I know is, there is a file in `/usr/share/fonts/X11/misc/fonts.alias` which tell us that this is an alias for the font name `6x13`. 

So I searched inside `/usr/share/fonts/X11/misc/` and found the file: `6x13-ISO8850-1.pcf.gz`. 

I used `gunzip` on the file but was unable to install it in the default manner through the GUI by clicking `install`. (The installation fails and you get a message `Install Failed`; how depressing!)

Luckily, I found this [Stack Overflow](https://askubuntu.com/questions/763075/font-manager-fails-in-ubuntu-16-04) about `font-manager` failing to install fonts. 

I went ahead and installed `font-manager` with `apt-get install font-manager` and then right-clicked `6x13-ISO8850-1.pcf` and scrolled through my applications until I got to `font-manager` and installed it with that. 

Next, just open terminal window and then select `Edit` --> `Preferences` --> check `Custom font: Fixed SemiCondensed 10`.

Now your terminal should look just like XTerm! Hopefully this saves someone 2 hours.
