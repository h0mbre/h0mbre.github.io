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

From `https://www.media.mit.edu/pia/Research/deepview/exif.html`, ***Basically, Exif file format is the same as JPEG file format. Exif inserts some of image/digicam information data and thumbnail image to JPEG in conformity to JPEG specification. Therefore you can view Exif format image files by JPEG compliant Internet browser/Picture viewer/Photo retouch software etc. as a usual JPEG image files.***

So Exif inserts metadata type information into images in conformity with the JPEG spec, and there exists no shortage of programs/utilities which helpfully parse this data out. 

## Getting Started
We'll be using Python3 to build a rudimentary mutation fuzzer that subtly (or not so subtly) alters valid Exif-filled JPEGs and feeds them to a parser hoping for a crash. We'll also be working on an x86 Kali Linux distro. 

First thing's first, we need a valid Exif-filled JPEG. A Google search for 'Sample JPEG with Exif' helpfully leads us to [this repo](https://github.com/ianare/exif-samples/tree/master/jpg). I'll be using the `Canon_40D.jpg` image for testing. 

## Getting to Know the JPEG and EXIF Spec
Before we start just scribbling Python into Sublime Text, let's first take some time to learn about the JPEG and Exif specification so that we can avoid some of the more obvious pitfalls of corrupting the image to the point that the parser doesn't attempt to parse it and wastes precious fuzzing cycles.

One thing to know from the [previously referenced specification overview](https://www.media.mit.edu/pia/Research/deepview/exif.html), is that all JPEG images start with byte values `0xFFD8` and end with byte values `0xFFD9`. This first couple of bytes are what are known as ['magic bytes'](https://en.wikipedia.org/wiki/List_of_file_signatures). This allows for straightforward file-type identification on \*Nix systems. 
```terminal_session
root@kali:~# file Canon_40D.jpg 
Canon_40D.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=11, manufacturer=Canon, model=Canon EOS 40D, orientation=upper-left, xresolution=166, yresolution=174, resolutionunit=2, software=GIMP 2.4.5, datetime=2008:07:31 10:38:11, GPS-Data], baseline, precision 8, 100x68, components 3
```

We can take the `.jpg` off and get the same output. 
```terminal_session
root@kali:~# file Canon
Canon: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=11, manufacturer=Canon, model=Canon EOS 40D, orientation=upper-left, xresolution=166, yresolution=174, resolutionunit=2, software=GIMP 2.4.5, datetime=2008:07:31 10:38:11, GPS-Data], baseline, precision 8, 100x68, components 3
```

If we hexdump the image, we can see the first and last bytes are in fact `0xFFD8` and `0xFFD9`.
```terminal_session
root@kali:~# hexdump Canon
0000000 d8ff e0ff 1000 464a 4649 0100 0101 4800
------SNIP------
0001f10 5aed 5158 d9ff 
```

Another interesting piece of information in the specification overview is that 'markers' begin with `0xFF`. There are several known static markers such as: 
+ the 'Start of Image' (SOI) marker: `0xFFD8`
+ APP1 marker: `0xFFE1`
+ generic markers: `0xFFXX`
+ the 'End of Image' (EOI) marker: `0xFFD9`

Since we don't want to change the image length or the file type, let's go ahead and plan to keep the SOI and EOI markers intact when possible. We don't want to insert `0xFFD9` into the middle of the image for example as that would truncate the image or cause the parser to misbehave in a non-crashy way. 'Non-crashy' is a real word. Also, this could be misguided and maybe we should be randomly putting EOI markers in the byte stream? Let's see. 

## Starting Our Fuzzer
The first thing we'll need to do is extract all of the bytes from the JPEG we want to use as our 'valid' input sample that we'll of course mutate. 

Our code will start off like this:
```python
#!/usr/bin/env python3

import sys

# read bytes from our valid JPEG and return them in a mutable bytearray 
def get_bytes(filename):

	f = open(filename, "rb").read()

	return bytearray(f)

if len(sys.argv) < 2:
	print("Usage: JPEGfuzz.py <valid_jpg>")

else:
	filename = sys.argv[1]
	data = get_bytes(filename)
```



