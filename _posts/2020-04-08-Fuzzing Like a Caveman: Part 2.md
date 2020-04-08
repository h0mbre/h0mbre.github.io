---
layout: single
title: Fuzzing Like A Caveman, Part 2
date: 2020-04-08
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
  - C++
---

## Introduction
In this episode of 'Fuzzing like a Caveman' we'll just be looking at improving the performance of our previous fuzzer. This means there won't be any wholesale changes, we're simply looking to improve upon what we already had in the previous post. This means we'll still end up walking away from this blogpost with a very basic mutation fuzzer (please let it be faster!!) and hopefully some more bugs on a different target. 

I feel the need to add a **DISCLAIMER** here that I am not a professional developer, far from it. I'm simply not experienced enough with programming at this point to recognize opportunities to improve performance the way a more seasoned programmer would. I'm going to use my crude skillset and my limited knowledge of programming to improve our previous fuzzer, that's it. The code produced will not be pretty, it will not be perfect, but it will be *better* than what we had in the previous post.  
