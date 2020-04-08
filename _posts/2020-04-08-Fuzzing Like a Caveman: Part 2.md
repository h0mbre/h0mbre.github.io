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

Let's take a moment to define 'better' in the context of this blog post as well. What I mean by 'better' here is that we can iterate through n fuzzing iterations faster, that's it. We'll take the time to completely rewrite the fuzzer, use a cool language, pick a hardened target, and employ more advanced fuzzing techniques at a later date. :)

***Obviously, if you haven't read the previous post you will be LOST!***

## Analyzing Our Fuzzer 
Our last fuzzer, quite plainly, worked! We found some bugs in our target. But we knew we left some optimizations on the table when we turned in our homework. Let's again look at the fuzzer from the last post (with minor changes for testing purposes):
```python
#!/usr/bin/env python3

import sys
import random
from pexpect import run
from pipes import quote
import time

# read bytes from our valid JPEG and return them in a mutable bytearray 
def get_bytes(filename):

	f = open(filename, "rb").read()

	return bytearray(f)

def bit_flip(data):

	num_of_flips = int((len(data) - 4) * .01)

	indexes = range(4, (len(data) - 4))

	chosen_indexes = []

	# iterate selecting indexes until we've hit our num_of_flips number
	counter = 0
	while counter < num_of_flips:
		chosen_indexes.append(random.choice(indexes))
		counter += 1

	for x in chosen_indexes:
		current = data[x]
		current = (bin(current).replace("0b",""))
		current = "0" * (8 - len(current)) + current
		
		indexes = range(0,8)

		picked_index = random.choice(indexes)

		new_number = []

		# our new_number list now has all the digits, example: ['1', '0', '1', '0', '1', '0', '1', '0']
		for i in current:
			new_number.append(i)

		# if the number at our randomly selected index is a 1, make it a 0, and vice versa
		if new_number[picked_index] == "1":
			new_number[picked_index] = "0"
		else:
			new_number[picked_index] = "1"

		# create our new binary string of our bit-flipped number
		current = ''
		for i in new_number:
			current += i

		# convert that string to an integer
		current = int(current,2)

		# change the number in our byte array to our new number we just constructed
		data[x] = current

	return data

def magic(data):

	magic_vals = [
	(1, 255),
	(1, 255),
	(1, 127),
	(1, 0),
	(2, 255),
	(2, 0),
	(4, 255),
	(4, 0),
	(4, 128),
	(4, 64),
	(4, 127)
	]

	picked_magic = random.choice(magic_vals)

	length = len(data) - 8
	index = range(0, length)
	picked_index = random.choice(index)

	# here we are hardcoding all the byte overwrites for all of the tuples that begin (1, )
	if picked_magic[0] == 1:
		if picked_magic[1] == 255:			# 0xFF
			data[picked_index] = 255
		elif picked_magic[1] == 127:		# 0x7F
			data[picked_index] = 127
		elif picked_magic[1] == 0:			# 0x00
			data[picked_index] = 0

	# here we are hardcoding all the byte overwrites for all of the tuples that begin (2, )
	elif picked_magic[0] == 2:
		if picked_magic[1] == 255:			# 0xFFFF
			data[picked_index] = 255
			data[picked_index + 1] = 255
		elif picked_magic[1] == 0:			# 0x0000
			data[picked_index] = 0
			data[picked_index + 1] = 0

	# here we are hardcoding all of the byte overwrites for all of the tuples that being (4, )
	elif picked_magic[0] == 4:
		if picked_magic[1] == 255:			# 0xFFFFFFFF
			data[picked_index] = 255
			data[picked_index + 1] = 255
			data[picked_index + 2] = 255
			data[picked_index + 3] = 255
		elif picked_magic[1] == 0:			# 0x00000000
			data[picked_index] = 0
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 128:		# 0x80000000
			data[picked_index] = 128
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 64:			# 0x40000000
			data[picked_index] = 64
			data[picked_index + 1] = 0
			data[picked_index + 2] = 0
			data[picked_index + 3] = 0
		elif picked_magic[1] == 127:		# 0x7FFFFFFF
			data[picked_index] = 127
			data[picked_index + 1] = 255
			data[picked_index + 2] = 255
			data[picked_index + 3] = 255
		
	return data

# create new jpg with mutated data
def create_new(data):

	f = open("mutated.jpg", "wb+")
	f.write(data)
	f.close()

def exif(counter,data):

    command = "exif mutated.jpg -verbose"

    out, returncode = run("sh -c " + quote(command), withexitstatus=1)

    if b"Segmentation" in out:
    	f = open("pycrashes/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Segfault!")

    elif b"Floating" in out:
    	f = open("pycrashes/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Floatingpoint!")

    #if counter % 100 == 0:
    #	print(counter, end="\r")

if len(sys.argv) < 2:
	print("Usage: JPEGfuzz.py <valid_jpg>")

else:
	start = time.time()
	filename = sys.argv[1]
	counter = 0
	data = get_bytes(filename)
	while counter < 10000:
		functions = [0, 1]
		picked_function = random.choice(functions)
		picked_function = 1
		if picked_function == 0:
			mutated = magic(data)
			create_new(mutated)
			exif(counter,mutated)
		else:
			mutated = bit_flip(data)
			create_new(mutated)
			exif(counter,mutated)

		counter += 1
	end = int((time.time() - start) * 1000)
	print("Execution Time: {}ms".format(end))
```

You may notice a few changes. We've:
+ commented out the print statement for  the iterations counter every 100 iterations,
+ added print statements to notify us of any Segfaults or any Floating point exceptions,
+ hardcoded 10k iterations,
+ added timing mechanisms that will print execution time when complete
+ added this line: `picked_function = 1` temporarily so that we eliminate any randomness in our testing and we only stick to one mutation method (`bit_flip()`)
