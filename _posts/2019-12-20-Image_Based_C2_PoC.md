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

## Picking A Trusted Domain
After some research, I settled on Imgur. Imgur has some advantages to it, you can upload images anonymously and also anonymously create albums that are not viewable to casual site-goers. 

One large drawback is that anonymously uploaded images are not indexed and searchable in the 'Gallery.' This would mean that in order to complete tasking, the tasking-side of the framework would have to be authenticated. But we will make do! (There are lots of different ways you can configure this communication paradigm, my way is not the best. Maybe I'm saving something better for later...)

## Creating A Steganography Method
This is where I spent the most time. `JPEG` files are unreliable when uploaded to Imugr as they do not retain their binary integrity. This is by design obviously, so `JPEG` is out as a file format. (Though that didn't stop me from trying for multiple nights!) After some early research, I discovered that `PNG` files contain a fourth pixel value known as an 'alpha-channel'. This alpha-channel value determines the opacity of that specific pixel. In the around 30 `PNG` files I examined, all alpha-channels were set to `255`. 


