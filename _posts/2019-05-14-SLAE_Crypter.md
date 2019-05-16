---
layout: single
title: SLAE Assignment 7 -- Custom Crypter
date: 2019-5-15
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

## Introduction

The 7th and final assignment for SLAE was create a custom encryption/decryption scheme for our shellcode. For the purposes of this excercise I chose to work with python. This assignment was a blast. Since its the last assignment, I decided to have some fun with it and went for novelty over strong encryption. I wanted a decryption scheme that only required shellcode input, so I designed the decryption function to brute force its own key!

## Encryption Process

My encryption scheme uses some fictional hacker lore as seed terms to generate a keyspace that ends up being a little over 1.4 million keys. I was shocked by how fast a computer running a poorly written python script can iterate through that many keys! At a high-level, the encryption function does the following:
+ takes shellcode input in the format of `\\xaa\\bb\\cc...`,
+ pads the shellcode with `\\xff` bytes to get it to a multiple of `16` (AES requires key sizes of n\*16),
+ creates an `iv` (initilialization vector of `13371337133713371`),
+ generates a keyspace with seed character names from hacker movies,
+ encrypts `input + padding` with randomly chosen `key` and `iv`, and
+ prints shellcode in format thats compatible with the decryption process.

## Decryption Process

The decryption scheme is straightforward. The script iterates through the entire keyspace decrypting the input shellcode with each key until it spots our `\\xff` padding and then it knows it has found the right key and prints the output. I picked this concept up from the SLAE coursework itself, it was awesome to apply it to python.

## Execution Process

For execution, the script just appends a `shellcode.c` writing process onto the decryption function and then compiles and runs that file. 

## Usage

## Crypter!!!

```python
from Crypto.Cipher import AES
from Crypto.Random import random
import argparse
import random
import sys
import os

#doing argument parsing
parser = argparse.ArgumentParser(add_help=True)
parser.add_argument("inp", type=str, help="shellcode to encrypt/decrypt/execute")
parser.add_argument("-e", "--encrypt", help="encrypt shellcode",
                    action="store_true")
parser.add_argument("-d", "--decrypt", help="decrypt shellcode",
                    action="store_true")
parser.add_argument("-x", "--execute", help="execute shellcode",
                    action="store_true")
args = parser.parse_args()
inp = args.inp
inp = inp.replace("\\x","")
shellcode = inp.decode("hex")

#setting up some globals
iv = "1337" * 4

#this is where we generate our key space, a little over 1.4 million keys
#Hackers(1995), Mr.Robot(2015), Wargames(1983), Blackhat(2015), Swordfish(2001)
nameList = ["Kate Libby_", "Ramon Sanch", "Paul Cook__", "Eugene Belf", "Dade Murphy", "Joey Pardel", "Em Goldstei", "Elliot Alde", "Darlene____", "Tyrell Well", "White Rose_", "Falken_____", "David______", "Nick Hathaw", "Chen Lien__", "Stanley____"]

numGen = list(range(10000,100000))

keyList = []

for x in nameList:
	for y in numGen:
		keyList += [x + str(y)]

def encrypt():
	try:
		global shellcode
		global iv
		global keyList
		key = random.choice(keyList)

		#Let's get our shellcode up to 32 bytes (has to be multiple of 16)

		shellPad = 32 - len(shellcode)

		shellPadBytes = b'\xff' * shellPad

		shellcode = shellPadBytes + shellcode

		#This is where we do our actual encryption!
		aes = AES.new(key, AES.MODE_CBC, iv)
		data = shellcode
		encd = aes.encrypt(data)

		#Let's get it into printable format!
		output = "" 

		for x in bytearray(encd):
			output += "\\x"
			output += '%02x'% x

		output = output.replace("\\x", r'\\x')

		print("\n[+] Encrypted Shellcode: " + output)

	except:
		print "Something went wrong with the encryption process."


def decrypt():
	try:
		global shellcode
		global iv
		global keyList
		#here we're just trying every possible key until the decryption process spots our '\\xff\\xff...' tag and knows it found the right one
		print("\n[+] Bruteforcing key for decryption...")
		for x in keyList:
			aes = AES.new(x, AES.MODE_CBC, iv)
			decrypt = aes.decrypt(shellcode)
			output = "" 
			for x in bytearray(decrypt):		
				output += "\\x"
				output += '%02x'% x
			if "\\xff\\xff\\xff\\xff\\xff" not in output:
				continue
			else:
				output = output[28:]
				output = output.replace("\\x", r'\\x')				
				print("[+] Decrypted Shellcode: " + output)
				break
	
	except: 
		print "[!] Something went wrong with the decryption process."


def execute():
	try:
		global shellcode
		global iv
		global keyList
		#same decryption process as above
		for x in keyList:
			aes = AES.new(x, AES.MODE_CBC, iv)
			decrypt = aes.decrypt(shellcode)
			output = "" 
			for x in bytearray(decrypt):		
				output += "\\x"
				output += '%02x'% x
			if "\\xff\\xff\\xff\\xff\\xff" not in output:
				continue
			else:
				output = output[28:]
				output = output.replace("\\x", r'\x')				
				break
	
	except: 
		print "[!] Something went wrong with the decryption process."

	try:
		#just writing our output to a shellcode.c file and compiling/executing it
		code = output
		shellcodeFile = open("shellcode.c", "w")
		shellcodeFile.write("""#include<stdio.h>
#include<string.h>

unsigned char code[] = \\
\"""")
		shellcodeFile.close()
		shellcodeFile = open("shellcode.c", "a")
		shellcodeFile.write(code)
		shellcodeFile.close()
		shellcodeFile = open("shellcode.c", "a")
		shellcodeFile.write("""";

main()
{

	printf(\"Shellcode Length:  %d\\n\", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}""")
		shellcodeFile.close()

		os.system("gcc -fno-stack-protector -z execstack -m32 shellcode.c -o shellcode 2>/dev/null && ./shellcode")
	

	except:
		
		print "Something went wrong with the execution process"

#control flow depending on CLI args!
if args.encrypt:
	encrypt()
elif args.decrypt:
	decrypt()
elif args.execute:
	execute()
```
