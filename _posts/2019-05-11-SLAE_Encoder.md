---
layout: single
title: SLAE Assignment 4 -- Encoder
date: 2019-5-11
classes: wide
header:
  teaser: /assets/images/SLAE/SLAE.jpg
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
--- 
![](/assets/images/SLAE/SLAE.jpg)

## Introduction

Assignment 4 is create a custom encoder and decoder for some shellcode. For this excercise, I stuck with a simple `execve` shellcode which will execute `/bin/sh`:
```terminal_session
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

## Encoder

We need to encode the aforementioned shellcode and an easy way to accomplish this is with a higher level language such as python. I haven't really done much python with bytearrays so let's see how it works step by step.

The first thing we want to do is introduce our pristine shellcode to our python script (note that we are using python3 for this).

```python
execve = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
```

According to this [stackoverflow entry,](https://stackoverflow.com/questions/2592764/what-does-a-b-prefix-before-a-python-string-mean), the lower-case `b` in our variable definition makes the string that follows a bytes string literal. What does this mean? Basically, the expression establishes a `byte object` instead of a `Unicode str object` like we're accustomed to. So even though this entity has all of the superficial features or a regular string, it's actually a bytes object. Let's do some comparisons so that we can solidify this difference in our minds.

```python
byteObject = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
strObject = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

print("The byteObject is " + str(len(byteObject)) + " long.")
print("The strObject is " + str(len(strObject)) + " long.")
```

If we run this code, we get the following output:

```terminal_session
root@kali:~# python3 encoder.py
The byteObject is 25 long.
The strObject is 25 long.
```

So they are the same length. Let's iterate a print command over them and see if we notice a difference. 

```python
byteObject = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
strObject = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

for x in byteObject:
	print(x)
```

Running this prints out our hex encoded segments as their decimal companions! This should make them very easy to work with.

```terminal_session
root@kali:~# python3 encoder.py
49
192
80
104
47
47
115
104
104
47
98
105
110
137
227
80
137
226
83
137
225
176
11
205
128
```

Let's do the same thing for our standard Unicode str object and see what the output is. 

```terminal_session
root@kali:~# python3 encoder.py
1
À
P
h
/
/
s
h
h
/
b
i
n

ã
P

â
S

á
°


Í

```

As you can see (or not!), it's printing our hex encoded segments as their Unicode counterparts, we can't work with this. Hopefully now we have a better grasp on how python is handling our `byte object`.

## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment3)





