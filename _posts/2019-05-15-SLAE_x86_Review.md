---
layout: single
title: SLAE x86 Review
date: 2019-5-15
classes: wide
header:
  teaser: /assets/images/SLAE/SLAE.jpg
tags:
  - SLAE
  - Linux
  - x86
  - shellcoding
  - encryption
  - assembly
  - python
--- 
![](/assets/images/SLAE/SLAE.jpg)

## Introduction

I recently completed the final assignment for the [x86 Assembly Language and Shellcoding on Linux](https://www.pentesteracademy.com/course?id=3) course from Pentester Academy. I'm currently awaiting to hear back on the result of my exam, but I couldn't wait to share my experience with the course. 

The course, as of the time of this post, is $149. This is a pretty cheap price compared to other certification courses, and I found the materials and course structure to be well worth the money. 

The course advertises the domains of knowledge covered by the course on the linked page above, but at a very high-level the course covered:
+ CPU architecture fundamentals,
+ GNU Debugger, 
+ IA-32 Assembly language,
+ Python scripting, 
+ Shellcoding for Linux, and
+ Encoders, Decoders, Crypters

This doesn't really tell the whole story or even come close but these were my main takeaways. 

I took this course because it was almost universally recommended by every SLAE certified person I had spoken to or blog I had read. It was also mentioned as a great on-ramp to CTP/OSCE which is my next goal. I didn't really know what to expect from the course at all, but I ended up being extremely pleased with my decision. 

## Prereqs

I honestly didn't have any knowledge of Assembly, CPU architecture, or shellcoding when I signed up so don't think you need to know anything about those. I would say you need the following skills to comfortably complete the course:
+ Linux command line,
+ ability to write Python scripts, and
+ puzzle-solving mindset.

That's really it. If you can script Python, or can work with Python comfortably enough to go find code examples and lift concepts out of them to apply to your script, you are good to go. I would say a knowledge of the types of shellcode payloads (ie. bind/reverse shells) is a bonus but not required. You don't have to be a professional pentester to take the course. This course is super amenable to people of every experience level. Don't think that the course will be easy because of this, but you will not need to be an expert in anything before starting. 

## Managing Expectations

I found the course to be fairly straightforward as far as picking up the concepts as they were taught. I only had to rewatch 2-3 videos multiple times to understand them thoroughly and I am not supremely talented in this stuff by any means. However, I found the certification assignments to be **MUCH** more difficult than the course material. Things went from a `4/10` in difficulty during the course to often an `7 or a 8/10` during the exam assignments (at least for me personally, maybe you will find it easier). 

You will have to do some homework on your own and Google concepts that are giving you a hard time. Vivek expects you to know the previous video's concepts well when you begin a new video, there is little review. Definitely follow along with him during his videos and do exactly as he's doing as he does it. 

**Do the GNU Debugger material included in the course materials.** It's such a worthwhile and useful tool to learn and will help you immensely when you're Assembly isn't working exactly like you thought it would.  

## Materials

The course comes in 3 separate download links sent via email and contains several zip files. There are around 25 videos and a bunch of code examples included in the courseware. The quality of the materials is great, they are recorded seemingly on Vivek's laptop webcam and have a lot of charm to them. 

The course also contains large portions, perhaps even the entirety (??), of a separate Pentester Academy course entitled GNU Debugger Megaprimer. This is a huge win for the price. 

## Knowledge Domains

### GNU Debugger

It's not really advertised heavily but the material includes a large portion of a separate course from Pentester Academy entitled [GNU Debugger Megaprimer](https://www.pentesteracademy.com/course?id=4), which is a huge bonus and makes the price even more reasonable. The GNU Debugger, known as GDB, is an extremely flexible and useful tool to master. According to the [GDB Project Site](https://www.gnu.org/software/gdb/), GDB is used for 4 main things:
+ Start your program, specifying anything that might affect its behavior.
+ Make your program stop on specified conditions.
+ Examine what has happened, when your program has stopped.
+ Change things in your program, so you can experiment with correcting the effects of one bug and go on to learn about another.

It also supports analysis for the following languages:
+ Ada
+ Assembly
+ C
+ C++
+ D
+ Fortran
+ Go
+ Objective-C
+ OpenCL
+ Modula-2
+ Pascal
+ Rust

GDB is very powerful tool and during the course you will use it a lot. I recommend following along with Vivek in the videos step-by-step and doing exactly what he does in real time. Even if you have no clue what he's doing or why, you will build up muscle-memory for useful commands, analysis techniques, etc. 

Becoming competent with GDB will enable you do a lot of different information security-related things and develop several disparate skillsets. 

I highly recommend you follow [these instructions](https://nuc13us.wordpress.com/2015/02/01/installing-gdb-peda-in-ubuntu/) and install Peda. It will make life a whole lot easier as it automatically performs several useful GDB utilities as you step through your programs. 

Learning GDB is a bit like learning to walk, it's a simple yet effective tool for getting where you want to go and doing what you want to do. 

### IA-32 Assembly

This is the meat and potatoes of the course. You will not become an Assembly expert in my opion, but you will definitely learn some great fundamentals and at least be positioned to write some really cool Assembly code. You will kind of be shocked how fast your skills progress in this area! 

I'm just a noob and not extremely experienced in information security yet, so I honestly can't say whether or not I will ever use the Assembly I learned in the course going forward outside of OSCE. But I can tell you this: programming these Assembly assignments in the course were some of the most challenging, fun, and rewarding things that I've done yet. I had an absolute blast with these assignments. This is probably my favorite certification course that I've taken.

I felt like the course taught you a new language and then gave you a set of logic puzzles to solve in the new language and said "have fun." Don't expect Vivek to do much hand holding, he expects you to Google things you do not quite understand. There isn't much review from video to video; however, Vivek does a great job of doing **every** step for every code iteration. This is great programming for you and helps you develop very thorough habits. **Please** do yourself a favor and follow along with his videos doing what he is doing. Do not just watch the video and then go to the next video, you will not get as much out of the course. 

### Python Scripting

I feel like a good working knowledge of Python is definitely a pre-requisite for this class. If you can program in C, even better. I was surprised how much Python the course included and I wasn't mentally prepared for that. Luckily, I had just spent a lot of time the previous month writing Python scripts and that knowledge definitely came in handy. 

You will primarily be using Python on the exam assignments to write your shellcode encoder and crypter. 

I can also say that the hours I sunk into those assignments definitely improved my ability to write useful Python scripts. Take a look at some of the Python scripts in my [SLAE Repo](https://github.com/h0mbre/SLAE) for reference.

### Shellcoding

After learning the Assembly fundamentals, you will begin shellcoding. Shellcoding, in the context of this course, is the process of constructing a payload that will run your evil code on the victim's host. It is incredible how gratifying this can be. After all the blood sweat and tears of making your Assembly work and you see that `/bin/sh` prompt appear when you run your code, and you show your wife and she goes "Oh...cool...", and you do a little shellcode dance, it's the best. 

One of the coolest things I picked up from the course was that there are so many different ways to shellcode for the same effect. Writing a shellcode that will spawn a `/bin/sh` can be done in a myriad of ways and it's really just one step removed from 'Hello World' in the shellcoding arena. Given even more complicated tasks, you will have a huge range of possible solutions and you will have a blast thinking of alternative ways to achieve your goals. This is the highlight of the course material. 

### Encoders/Decoders and Crypters

In the course materials you will learn about Encoders/Decoders and Crypters for your shellcode, but the exam assignments really give you a ton of flexibility to create your own solutions. These 2 assignments were my favorite ones. 

An encoder/decoder simply alters your shellcode in a known way in order to avoid simplistic fingerprinting. A crypter simply encrypts your payload to meet the same goal. 

Figuring out a custom encoding scheme and then getting the decoder written in Assembly and working was extremely gratifying. You could easily take a simplistic approach to these exam assignments, but challenge yourself! Let's see how complex you can get your code and have it function. Your only limit is your imagination. 

## Exam

The exam format is to create 7 public blog posts containing your solutions and explanations for each assignment. I found this exam format to be really great. It gave me time to thoroughly research all the topics and put together higher-quality products. It was low-pressure and really allowed me to get familiar with the topics. 

When you have completed your blog posts, you simply send Pentester Academy an email with all the links to your blog posts and they will eventually evaluate them and tell you how you did. 

**Do the exam assignments!** 

I probably did 80% of my learning during the exam assignments. The difficulty level is dramatically increased from the course material to the exam assignments so don't cheat yourself. Get as much as you can out of the course!

## Summary

I had a blast with this course and will be recommending it to whoever asks and probably many who don't. If you're bored or looking for a challenge, you should sign up. If you are even remotely interested in learning the debugger, learning Assembly, or might want to try RE or something related, this is probably a great introduction to that type of work. I definitely intend to take the x86-64 version after OSCE. 

You can find my SLAE posts below, and feel free to contact me on Twitter (`@h0mbre_`) or NetSecFocus if you have any questions about the course. 

Thanks for reading!

Thanks to `@epi052` and `@AnubisOnSec` for their help! 

#### SLAE Assignments

[Assignment 1:](https://h0mbre.github.io/SLAE_TCP_Bind_Shell/)
[Assignment 2:](https://h0mbre.github.io/SLAE_TCP_Rev_Shell/)
[Assignment 3:](https://h0mbre.github.io/SLAE_Egg_Hunter/)
[Assignment 4:](https://h0mbre.github.io/SLAE_Encoder/)
[Assignment 5:](https://h0mbre.github.io/SLAE_MSF_Analysis/)
[Assignment 6:](https://h0mbre.github.io/SLAE_Polymorphic_Shellcode/)
[Assignment 7:](https://h0mbre.github.io/SLAE_Crypter/)


