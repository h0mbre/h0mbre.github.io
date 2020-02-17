---
layout: single
title: HEVD Exploits -- Windows 7 x86-64 Uninitialized Stack Variable
date: 2020-02-09
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Exploit Dev
  - Drivers
  - Windows
  - x86-64
  - Shellcoding
  - Kernel Exploitation
  - Uninitialized Stack Variable
---

## Introduction
Continuing on with the Windows exploit journey, it's time to start exploiting kernel-mode drivers and learning about writing exploits for ring 0. As I did with my OSCE prep, I'm mainly blogging my progress as a way for me to reinforce concepts and keep meticulous notes I can reference later on. I can't tell you how many times I've used my own blog as a reference for something I learned 3 months ago and had totally forgotten. 

This series will be me attempting to run through every exploit on the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). **I will be using HEVD 2.0**. I can't even begin to explain how amazing a training tool like this is for those of us just starting out. There are a ton of good blog posts out there walking through various HEVD exploits. I recommend you read them all! I referenced them heavily as I tried to complete these exploits. Almost nothing I do or say in this blog will be new or my own thoughts/ideas/techniques. There were instances where I diverged from any strategies I saw employed in the blogposts out of necessity or me trying to do my own thing to learn more.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits.

## HEVD Series Change
I will no longer be using Python ctypes to write exploits. We will be using C++ from now on. I realize this is a big change for people following along so I've commented the code heavily. 

I will no longer be doing x86 exploits, only x86-64 from now on. 

## Goal
This one is pretty straightforward, we'll be attacking HEVD as normal, this time looking at the uninitialized stack variable bug class. While this isn't super common (I don't think?), there is a very neat API we can leverage from userland to spray the kernel stack and set ourselves up nicely so that we can get control over a called function pointer value. 

## IOCTL Things

Call graph for our desired function:

![](/assets/images/AWE/svioctl.PNG)

We will be targeting a vulnerable function that triggers an uninitialized stack variable vulnerablity. We can see from the `IrpDeviceIoCtlHandler` function in IDA that we branch to our desired call in the bottom left after failing a `jz` after comparing our IOCTL value (`eax`) with `0x22202B` and then subtracting another `0x4` and successfully triggering a `jz`. So we can conclude that our desired IOCTL is `0x22202B` + `0x4`, which is `0x22202F.`

We'll write some code that creates a handle to the driver and sends a phony payload just to see if we break on that memory location as anticipated. 

You'll notice from our image above that the targeted block of instructions is denoted by a location of `loc_16A27`. We'll go the more realistic route here and pretend we don't have the driver symbols and just set a breakpoint on the loaded module name `HEVD` (if you're confused about this, enter `lm` to check the loaded modules in `kd>` and take a gander at the list), and then add a breakpoint at `!HEVD+0x6a27`, the `1` in the location is actually assuming a base address of  `0x0000000000010000`, so we can remove that and dynamically set the breakpoint at the offset. (I think?) BP is set, let's run our code and see if we hit it, we'll send a junk payload of `AAAAAAAA` right now for testing purposes. 

Our code will look like this at this point:
```cpp
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>

#define DEVICE_NAME     "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL           0x22202F

// grabbing a handle to our driver with CreateFileA
HANDLE get_handle(const char* device_name)
{
	// already a big advantage to using C++, we have access to the Windows constant values
	HANDLE hevd = CreateFileA(device_name,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	
	// this will help us avoid lots of if statements as we can just loop until a condition is true, not particularly helpful here, but we'll be doing it more
	do
	{
		if (hevd == INVALID_HANDLE_VALUE)
		{
			std::cout << "[!] Failed to retrieve handle to the device-driver with error-code:" << ("%x", GetLastError()) << "\n";
			break;
		}

		std::cout << "[*] Successfully retrieved handle to device-driver:" << ("%p", hevd) << "\n";
	
	} while (0); 

	return hevd;
}

void interact(HANDLE result)
{
	//specify the bytes we want to send, in this case 8 * \x41
	BYTE inputBuff[] = "AAAAAAAA";
	
	//this parameter of DeviceIoControl has to actually exist so we have to make it, but we don't care about it
	DWORD bytesRet = 0;

	//calling DeviceIoControl, returns non-0 if success, which is a BOOL basically because it can be True (anything) or False (0)
	//we're not specifying an output buffer in this case as we don't want any data returned from this IOCTL in particular, so that's null and it's size is 0
	BOOL success = DeviceIoControl(result,
		IOCTL,
		inputBuff,
		sizeof(inputBuff),
		NULL,
		0,
		&bytesRet,
		NULL);

	if (success) 
	{
		std::cout << "[*] Payload sent to driver successfully.";
	}
	else
	{
		std::cout << "[!] Payload failed with error code: " << ("%x", GetLastError()) << "\n";
	}
}

int main()
{
	// call our get_handle function with our hardcoded constant and return the result 
	HANDLE result = get_handle(DEVICE_NAME);

	// call our interact function which calls DeviceIoControl and requires our returned handle
	interact(result);

	return 0;
}
```

![](/assets/images/AWE/wehit.PNG)

As you can see, we hit our breakpoint so our IOCTL is correct. Let's figure out what this function actually does. 

## Breaking Down `TriggerUninitializedStackVariable`
Once we hit our code block, there's a call to `UninitializedStackVariableIoctlHandler` which in turn calls `TriggerUninitializedStackVariable`. We can see a test inside this IOCTL handler to check whether or not our buffer was null. We can see this because it calls a `test rcx, rcx` after placing the user buffer into `rcx`. You can read more about [test here.](https://en.wikipedia.org/wiki/TEST_(x86_instruction)). 

![](/assets/images/AWE/usvih.PNG)

After that, we will fail the default `jz` case and end up calling `TriggerUninitializedStackVariable`. This is what the beginning of the function looks like when we inspect in IDA.

![](/assets/images/AWE/usvbeg.PNG)

We see there's a `[ProbeForRead]`(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread) call and then we're loading a value of `0xBAD0B0B0` into `edx` and then executing a `cmp` between that arbitrary static value and `ebx`. This is probably a compare between our user provided buffer and this static value. Obviously there are two branches from this.

The red branch, which means the compare returned a `0` meaning the buffer matched the hardcoded value, looks to be taking the hardcoded value and loading it onto the stack and then also initializing a second variable called `UninitializedStackVariableObjectCallback` by loading it's value onto the stack as well. 

The green bracnch simply takes whatever value is on the stack at `[rsp+0x128+var_108]` and loads it into `edx`. One of the biggest differneces here is that no value is placed on the stack at `[rsp+0x128+var_100]` from `rax`. This is curious because, in the next block of code, where the two paths converge, we see that stack value being loaded into `r11` and then a call to `r11`. 

![](/assets/images/AWE/uninit.PNG)

![](/assets/images/AWE/zecall.PNG)

Since a known value was never placed on the stack to be loaded into `r11`, we're calling a function pointer that could lead to undefined behavior. The source code might look something like this in pseudo:
```cpp
//our code, uninitialized, declared but not given a value 
STRUCT variable;

//a better way is to make it NULL initially and then you can check if its NULL before calling it 
STRUCT variable = { 0 };
```

Because it's never given a value explicitly before called, the value could end up being whatever is on the stack at the time the function pointer is called. This in and of itself isn't extremely useful to us since we haven't yet discovered a way to put pointers to our shellcode on the stack, until we read the [FuzzySec](https://www.fuzzysecurity.com/tutorials/expDev/17.html) and [j00ru](https://j00ru.vexillium.org/2011/05/windows-kernel-stack-spraying-techniques/) blogs. 





