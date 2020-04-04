---
layout: single
title: Fuzzing Like A Caveman
date: 2020-04-04
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - fuzzing
  - exif
  - parsing
  - Python
  - jpeg
  - mutation
---

## Introduction
I've been passively consuming a lot of fuzzing-related material in the last few months as I've primarily tried to up my Windows exploitation game from Noob-Level to 1%-Less-Noob-Level, and I've found it utterly fascinating. In this post I will show you how to create a really simple mutation fuzzer and hopefully we can find some crashes in some open source projects with it. 

The fuzzer we'll be creating is from just following along with [@gynvael's](https://twitter.com/gynvael?ref_src=twsrc%5Egoogle%7Ctwcamp%5Eserp%7Ctwgr%5Eauthor) [fuzzing tutorial on YouTube](https://www.youtube.com/watch?v=BrDujogxYSk&). I had no idea that Gynvael had streams so now I have dozens more hours or content to add to the never ending list of things to watch/read. 

I must also mention that [Brandon Faulk's](https://twitter.com/gamozolabs) [fuzzing streams](https://www.youtube.com/user/gamozolabs/videos) are incredible. I don't understand roughly 99% of the things Brandon says, but these streams are captivating. My personal favorites so far have been his fuzzing of `calc.exe` and `c-tags`. He also has this wonderful introduction to fuzzing concepts video here: [NYU Fuzzing Talk](https://www.youtube.com/watch?v=SngK4W4tVc0). 

## Picking a Target
I wanted to find a binary that was written in C or C++ and parsed data from a file. One of the first things I came across was binaries that parse Exif data out of images. 

From [https://www.media.mit.edu/pia/Research/deepview/exif.html], ***Basically, Exif file format is the same as JPEG file format. Exif inserts some of image/digicam information data and thumbnail image to JPEG in conformity to JPEG specification. Therefore you can view Exif format image files by JPEG compliant Internet browser/Picture viewer/Photo retouch software etc. as a usual JPEG image files.***


