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

If we want to see how this data looks, we can print the first 10 or so byte values in the array and see how we'll be interacting with them. We'll just temporarily add something like:
```python
else:
	filename = sys.argv[1]
	data = get_bytes(filename)
	counter = 0
	for x in data:
		if counter < 10:
			print(x)
		counter += 1
```

Running this shows that we're dealing with neatly converted decimal integers which makes everything much easier in my opinion.
```terminal_session
root@kali:~# python3 fuzzer.py Canon_40D.jpg 
255
216
255
224
0
16
74
70
73
70
```

Let's just quickly see if we can create a new valid JPEG from our byte array. We'll add this function to our code and run it.
```python
def create_new(data):

	f = open("mutated.jpg", "wb+")
	f.write(data)
	f.close()
```

So now we have `mutated.jpg` in our directory, let's hash the two files and see if they match. 
```terminal_session
root@kali:~# shasum Canon_40D.jpg mutated.jpg 
c3d98686223ad69ea29c811aaab35d343ff1ae9e  Canon_40D.jpg
c3d98686223ad69ea29c811aaab35d343ff1ae9e  mutated.jpg
```

Awesome, we have two identical files. Now we can get into the business of mutating the data before creating our `mutated.jpg`. 

## Mutating
We'll keep our fuzzer relatively simple and only implement two different mutation methods. These methods will be:
+ bit flipping
+ overwriting byte sequences with Gynvael's 'Magic Numbers'

Let's start with bit flipping. `255` (or `0xFF`) in binary would be `11111111` if we were to randomly flip a bit in this number, let say at index number 2, we'd end up with `11011111`. This new number would be `223` or `0xDF`. 

I'm not entirely sure how different this mutation method is from randomly selecting a value from `0` - `255` and overwritng a random byte with it. My intuiton says that bit flipping is extremely similar to randomly overwriting bytes with an arbitrary byte. 

Let's go ahead and say we want to only flip a bit in 1% of the bytes we have. We can get to this number in Python by doing:
```python
num_of_flips = int((len(data) - 4) * .01)
```

We want to subtract 4 from the length of our bytearray because we don't want to count the first 2 bytes or the last 2 bytes in our array as those were the SOI and EOI markers and we are aiming to keep those intact. 

Next we'll want to randomly select that many indexes and target those indexes for bit flipping. We'll go ahead and create a range of possible indexes we can change and then choose `num_of_flips` of them to randomly bit flip. 
```python
indexes = range(4, (len(data) - 4))

chosen_indexes = []

# iterate selecting indexes until we've hit our num_of_flips number
counter = 0
while counter < num_of_flips:
	chosen_indexes.append(random.choice(indexes))
	counter += 1
```

Let's add `import random` to our script, and also add these debug print statements to make sure everything is working correctly. 
```python

print("Number of indexes chosen: " + str(len(chosen_indexes)))
print("Indexes chosen: " + str(chosen_indexes))
```

Our function right now looks like this: 
```python
def bit_flip(data):

	num_of_flips = int((len(data) - 4) * .01)

	indexes = range(4, (len(data) - 4))

	chosen_indexes = []

	# iterate selecting indexes until we've hit our num_of_flips number
	counter = 0
	while counter < num_of_flips:
		chosen_indexes.append(random.choice(indexes))
		counter += 1

	print("Number of indexes chosen: " + str(len(chosen_indexes)))
	print("Indexes chosen: " + str(chosen_indexes))
```

If we run this, we get a nice output as expected:
```terminal_session
root@kali:~# python3 fuzzer.py Canon_40D.jpg 
Number of indexes chosen: 79
Indexes chosen: [6580, 930, 6849, 6007, 5020, 33, 474, 4051, 7722, 5393, 3540, 54, 5290, 2106, 2544, 1786, 5969, 5211, 2256, 510, 7147, 3370, 625, 5845, 2082, 2451, 7500, 3672, 2736, 2462, 5395, 7942, 2392, 1201, 3274, 7629, 5119, 1977, 2986, 7590, 1633, 4598, 1834, 445, 481, 7823, 7708, 6840, 1596, 5212, 4277, 3894, 2860, 2912, 6755, 3557, 3535, 3745, 1780, 252, 6128, 7187, 500, 1051, 4372, 5138, 3305, 872, 6258, 2136, 3486, 5600, 651, 1624, 4368, 7076, 1802, 2335, 3553]
```

Next we need to actually mutate the bytes at those indexes. We need to bit flip them. I chose to do this in a really hacky way, feel free to implement your own solution. We're going to covert the bytes at these indexes to binary strings and pad them so that they are 8 digits long. Let's add this code and see what I'm talking about. We'll be converting the byte value (which is in decimal remember) to a binary string and then padding it with leading zeroes if it's less than 8 digits long. The last line is a temporary print statement for debugging.
```python
for x in chosen_indexes:
        current = data[x]
        current = (bin(current).replace("0b",""))
        current = "0" * (8 - len(current)) + current
```

As you can see, we have a nice output of binary numbers as strings. 
```terminal_session
root@kali:~# python3 fuzzer.py Canon_40D.jpg 
10100110
10111110
10010010
00110000
01110001
00110101
00110010
-----SNIP-----
```

Now for each of these, we'll randomly select an index, and flip it. Take the first one, `10100110`, if select index 0, we have a `1`, we'll flip it to `0`. 

Last considering for this code segment is that these are strings not integers remember. So the last thing we need to do is convert the flipped binary string to integer. 

We'll create an empty list, add each digit to the list, flip the digit we randomly picked, and the construct a new string from all the list members. (We have to use this intermediate list step since strings are mutable). Finally, we convert it to an integer again. 
