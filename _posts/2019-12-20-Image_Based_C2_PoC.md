---
layout: single
title: An Image-Based C2 Channel Proof-of-Concept 
date: 2019-12-20
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - C2
  - Red Teaming
  - Steganography 
  - Python
---

## Introduction
In mid-November I decided to try and start a project that would be both fun and educational. I settled on trying to come up with a somewhat creative C2 channel proof-of-concept that involved steganography and a somewhat trusted domain instead of bespoke infrastructure. I don't know much about Red Teaming, this will become apparent as you read this post. I'm mostly going off of high-level concepts I've gathered from passively consuming red teaming material that has passed over my Twitter timeline. I know there are agents/implants in networks that need to be tasked and that need to stealthily send data back to a C2 server. That's about it, folks!

I started by looking at open-source C2 channel concepts that involved trusted web applications or domains and found quite a few awesome projects, such as: [Slackor](https://github.com/Coalfire-Research/Slackor), [gcat](https://github.com/byt3bl33d3r/gcat), and [twittor](https://github.com/PaulSec/twittor). 

This helped me solidify my goals:
+ Build something that is fun, doesn't have to be effective/useful to leet Red Teamers
+ Create a unique steganography method (unique to me, without digging into academic research)
+ Make both the tasking and the response occur via image passing
+ No random base64 strings dumped on white space in an application
+ Utilize a trusted domain
+ Simulate an agent/implant with a Python script for now (I'm planning on writing a proper implant after some Windows exploit/internals studies in 2020)

With those goals in mind, let's proceed!

## 


