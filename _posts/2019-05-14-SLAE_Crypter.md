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

## Coming Soon!

```python
from Crypto.Cipher import AES
from Crypto.Random import random
import argparse
import random
import sys
import os

#just setting up a custom help message

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
