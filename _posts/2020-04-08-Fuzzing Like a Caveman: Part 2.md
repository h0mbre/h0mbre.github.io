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
In this episode of 'Fuzzing like a Caveman' we'll just be looking at improving the performance of our previous fuzzer. This means there won't be any wholesale changes, we're simply looking to improve upon what we already had in the previous post. This means we'll still end up walking away from this blogpost with a very basic mutation fuzzer (please let it be faster!!) and hopefully some more bugs on a different target. We won't really tinker with multi-threading or multi-processing in this post, we will save that for subsequent fuzzing posts. 

I feel the need to add a **DISCLAIMER** here that I am not a professional developer, far from it. I'm simply not experienced enough with programming at this point to recognize opportunities to improve performance the way a more seasoned programmer would. I'm going to use my crude skillset and my limited knowledge of programming to improve our previous fuzzer, that's it. The code produced will not be pretty, it will not be perfect, but it will be *better* than what we had in the previous post. It should also be mentioned that all testing was done on VMWare Workstation on an x86 Kali VM with 1 CPU and 1 Core. 

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
    	f = open("crashes2/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Segfault!")

    #if counter % 100 == 0:
    #	print(counter, end="\r")

if len(sys.argv) < 2:
	print("Usage: JPEGfuzz.py <valid_jpg>")

else:
	filename = sys.argv[1]
	counter = 0
	while counter < 1000:
		data = get_bytes(filename)
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
```

You may notice a few changes. We've:
+ commented out the print statement for  the iterations counter every 100 iterations,
+ added print statements to notify us of any Segfaults,
+ hardcoded 1k iterations,
+ added this line: `picked_function = 1` temporarily so that we eliminate any randomness in our testing and we only stick to one mutation method (`bit_flip()`)

Let's run this version of our fuzzer with some profiling instrumentation and we can really analyze how much time we spend where in our program's execution. 

We can make use of the `cProfile` Python module and see where we spend our time during 1,000 fuzzing iterations. The program takes a filepath argument to a valid JPEG file if you remember, so our complete command line syntax will be: `python3 -m cProfile -s cumtime JPEGfuzzer.py ~/jpegs/Canon_40D.jpg`.

After letting this run, we see our program output and we get to see where we spent the most time during execution. 
```
2476093 function calls (2474812 primitive calls) in 122.084 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     33/1    0.000    0.000  122.084  122.084 {built-in method builtins.exec}
        1    0.108    0.108  122.084  122.084 blog.py:3(<module>)
     1000    0.090    0.000  118.622    0.119 blog.py:140(exif)
     1000    0.080    0.000  118.452    0.118 run.py:7(run)
     5432  103.761    0.019  103.761    0.019 {built-in method time.sleep}
     1000    0.028    0.000  100.923    0.101 pty_spawn.py:316(close)
     1000    0.025    0.000  100.816    0.101 ptyprocess.py:387(close)
     1000    0.061    0.000    9.949    0.010 pty_spawn.py:36(__init__)
     1000    0.074    0.000    9.764    0.010 pty_spawn.py:239(_spawn)
     1000    0.041    0.000    8.682    0.009 pty_spawn.py:312(_spawnpty)
     1000    0.266    0.000    8.641    0.009 ptyprocess.py:178(spawn)
     1000    0.011    0.000    7.491    0.007 spawnbase.py:240(expect)
     1000    0.036    0.000    7.479    0.007 spawnbase.py:343(expect_list)
     1000    0.128    0.000    7.409    0.007 expect.py:91(expect_loop)
     6432    6.473    0.001    6.473    0.001 {built-in method posix.read}
     5432    0.089    0.000    3.818    0.001 pty_spawn.py:415(read_nonblocking)
     7348    0.029    0.000    3.162    0.000 utils.py:130(select_ignore_interrupts)
     7348    3.127    0.000    3.127    0.000 {built-in method select.select}
     1000    0.790    0.001    1.777    0.002 blog.py:15(bit_flip)
     1000    0.015    0.000    1.311    0.001 blog.py:134(create_new)
     1000    0.100    0.000    1.101    0.001 pty.py:79(fork)
     1000    1.000    0.001    1.000    0.001 {built-in method posix.forkpty}
-----SNIP-----
```
For this type of analysis, we don't really care about how many segfaults we had since we're not really tinkering much with the mutation methods or comparing different methods. Granted there will be some randomness here, as a crash would necessitate extra processing, but this will do for now. 

I snipped only the sections of code where we spent more than 1.0 seconds cumulatively. You can see we spent by far the most time in `blog.py:140(exif)`. A whopping 118 seconds out of 122 seconds total. Our `exif()` function seems to be a major problem in our performance. 

We can see that most of the time we spent underneath that function was directly related to the function, we see plenty of appeals to the `pty` module from our `pexpect` usage. Let's rewrite our function using `Popen` from the `subprocess` module and see if we can improve performance here!

Here is our redefined `exif()` function:
```python
def exif(counter,data):

    p = Popen(["exif", "mutated.jpg", "-verbose"], stdout=PIPE, stderr=PIPE)
    (out,err) = p.communicate()

    if p.returncode == -11:
    	f = open("crashes2/crash.{}.jpg".format(str(counter)), "ab+")
    	f.write(data)
    	print("Segfault!")

    #if counter % 100 == 0:
    #	print(counter, end="\r")
 ```

Here is our performance report:
```
2065580 function calls (2065443 primitive calls) in 2.756 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     15/1    0.000    0.000    2.756    2.756 {built-in method builtins.exec}
        1    0.038    0.038    2.756    2.756 subpro.py:3(<module>)
     1000    0.020    0.000    1.917    0.002 subpro.py:139(exif)
     1000    0.026    0.000    1.121    0.001 subprocess.py:681(__init__)
     1000    0.099    0.000    1.045    0.001 subprocess.py:1412(_execute_child)
 -----SNIP-----
 ```
 
 What a difference. This fuzzer, with the redefined `exif()` function performed the same amount of work in only 2 seconds!! That's insane! The old fuzzer: 122 seconds, new fuzzer: 2.7 seconds. What an improvement. This is an insane performance increase. Our new fuzzer does the same amount of work in 1/60th of the time. 
 
## New Fuzzer in C++
Let's try and rewrite our fuzzer in a new language, C++. First, let's get a good benchmark for us to perform against. We'll get our optimized Python fuzzer to iterate through 50,000 fuzzing iterations and we'll use the `cProfile` module again to get some fine-grained statistics about where we spend our time. 
```
102981395 function calls (102981258 primitive calls) in 141.488 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     15/1    0.000    0.000  141.488  141.488 {built-in method builtins.exec}
        1    1.724    1.724  141.488  141.488 subpro.py:3(<module>)
    50000    0.992    0.000  102.588    0.002 subpro.py:139(exif)
    50000    1.248    0.000   61.562    0.001 subprocess.py:681(__init__)
    50000    5.034    0.000   57.826    0.001 subprocess.py:1412(_execute_child)
    50000    0.437    0.000   39.586    0.001 subprocess.py:920(communicate)
    50000    2.527    0.000   39.064    0.001 subprocess.py:1662(_communicate)
   208254   37.508    0.000   37.508    0.000 {built-in method posix.read}
   158238    0.577    0.000   28.809    0.000 selectors.py:402(select)
   158238   28.131    0.000   28.131    0.000 {method 'poll' of 'select.poll' objects}
    50000   11.784    0.000   25.819    0.001 subpro.py:14(bit_flip)
  7950000    3.666    0.000   10.431    0.000 random.py:256(choice)
    50000    8.421    0.000    8.421    0.000 {built-in method _posixsubprocess.fork_exec}
    50000    0.162    0.000    7.358    0.000 subpro.py:133(create_new)
  7950000    4.096    0.000    6.130    0.000 random.py:224(_randbelow)
   203090    5.016    0.000    5.016    0.000 {built-in method io.open}
    50000    4.211    0.000    4.211    0.000 {method 'close' of '_io.BufferedRandom' objects}
    50000    1.643    0.000    4.194    0.000 os.py:617(get_exec_path)
    50000    1.733    0.000    3.356    0.000 subpro.py:8(get_bytes)
 35866791    2.635    0.000    2.635    0.000 {method 'append' of 'list' objects}
   100000    0.070    0.000    1.960    0.000 subprocess.py:1014(wait)
   100000    0.252    0.000    1.902    0.000 selectors.py:351(register)
   100000    0.444    0.000    1.890    0.000 subprocess.py:1621(_wait)
   100000    0.675    0.000    1.583    0.000 selectors.py:234(register)
   350000    0.432    0.000    1.501    0.000 subprocess.py:1471(<genexpr>)
 12074141    1.434    0.000    1.434    0.000 {method 'getrandbits' of '_random.Random' objects}
    50000    0.059    0.000    1.358    0.000 subprocess.py:1608(_try_wait)
    50000    1.299    0.000    1.299    0.000 {built-in method posix.waitpid}
   100000    0.488    0.000    1.058    0.000 os.py:674(__getitem__)
   100000    1.017    0.000    1.017    0.000 {method 'close' of '_io.BufferedReader' objects}
-----SNIP-----
```

50,000 iterations took us a grand total of 141 seconds, this is great performance compared to what we were dealing with. We previously took 122 seconds to do 1,000 iterations! Once again filtering on only time where we spent over 1.0 seconds, we see that we again spent most of our time in `exif()` but we also see some performance issues in `bit_flip()` as we spent 25 cumulative seconds there. Let's try to optimize that function a bit. 

Let's go ahead and repost what the old `bit_flip()` function looked like:
```python

