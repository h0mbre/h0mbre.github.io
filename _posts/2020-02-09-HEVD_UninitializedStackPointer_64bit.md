---
layout: single
title: HEVD Exploits -- Windows 7 x86 Uninitialized Stack Variable
date: 2020-02-09
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Exploit Dev
  - Drivers
  - Windows
  - x86
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

I will try to avoid 32 bit exploits where possible and focus solely on 64 bit (except this one, I hated this one lol).  

## Goal
This one is pretty straightforward, we'll be attacking HEVD as normal, this time looking at the uninitialized stack variable bug class. While this isn't super common (I don't think?), there is a very neat API we can leverage from userland to spray the kernel stack and set ourselves up nicely so that we can get control over a called function pointer value. 

## IOCTL Things

Call graph for our desired function:

![](/assets/images/AWE/svioctl.PNG)

We will be targeting a vulnerable function that triggers an uninitialized stack variable vulnerablity. We can see from the `IrpDeviceIoCtlHandler` function in IDA that we branch to our desired call in the bottom left after failing a `jz` after comparing our IOCTL value (`eax`) with `0x22202B` and then subtracting another `0x4` and successfully triggering a `jz`. So we can conclude that our desired IOCTL is `0x22202B` + `0x4`, which is `0x22202F.`

We'll write some code that creates a handle to the driver and sends a phony payload just to see if we break on that memory location as anticipated. 

You'll notice from our image above that the targeted block of instructions is denoted by a location of `loc_1571A`. We'll go the more realistic route here and pretend we don't have the driver symbols and just set a breakpoint on the loaded module name `HEVD` (if you're confused about this, enter `lm` to check the loaded modules in `kd>` and take a gander at the list), and then add a breakpoint at `!HEVD+0x571A`, the `1` in the location is actually assuming a base address of  `0x00010000`, so we can remove that and dynamically set the breakpoint at the offset. (I think?) BP is set, let's run our code and see if we hit it, we'll send a junk payload of `AAAA` right now for testing purposes. 

Our code will look like this at this point, I lifted the do-while loop right out of @TheColonial's [Capcom.sys YouTube video (must see)](https://www.youtube.com/watch?v=pJZjWXxUEl4):
```cpp
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>

//
// Defining just our driver name that it uses for IoCreateDevice and also the IOCTL code we use to reach our vulnerable function
#define DEVICE_NAME     "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL           0x22202F

HANDLE Get_Handle()
{
	HANDLE HEVD = CreateFileA(DEVICE_NAME,
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (HEVD == INVALID_HANDLE_VALUE)
	{
		std::cout << "[!] Unable to retrieve handle for HEVD, last error: " << GetLastError() << "\n";
		exit(1);
	}

	printf("[*] Successfully retrieved handle to HEVD: %X\n", HEVD);
	return HEVD;
}

int main()
{
	HANDLE HEVD = Get_Handle();

	// Just a dummy buffer so that we don't match the keyword value for BAD0B0B0
	char Input_Buffer[] = "\x41\x41\x41\x41";
	
	DWORD Dummy_Bytes = 0;

	// Trigger bug
	DeviceIoControl(HEVD,
		0x22202F,
		&Input_Buffer,
		sizeof(Input_Buffer),
		NULL,
		0,
		&Dummy_Bytes,
		NULL); 
}

```

![](/assets/images/AWE/wehit.PNG)

As you can see, we hit our breakpoint so our IOCTL is correct. Let's figure out what this function actually does. 

## Breaking Down `TriggerUninitializedStackVariable`
Once we hit our code block, there's a call to `UninitializedStackVariableIoctlHandler` which in turn calls `TriggerUninitializedStackVariable`. We can see a test inside this IOCTL handler to check whether or not our buffer was null. We can see this because it calls a `test ecx, ecx` after placing the user buffer into `ecx`. You can read more about [test here.](https://en.wikipedia.org/wiki/TEST_(x86_instruction)). 

![](/assets/images/AWE/usvih.PNG)

After that, we will fail the default `jz` case and end up calling `TriggerUninitializedStackVariable`. This is what the function looks like when we inspect in IDA.

![](/assets/images/AWE/usvbeg.PNG)

We see there's a `[ProbeForRead]`(https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread) call and then we're loading a value of `0xBAD0B0B0` into `eax` and then executing a `cmp` between that arbitrary static value and `esi`. This is probably a compare between our user provided buffer and this static value. Obviously there are two branches from this.

The shortest arrow will, which should be red, will be the code path we take if the zero flag is set, since `jnz` is the default case (green). So if our provided input is exactly `0xBAD0B0B0`, we will take this short jump and execute the next two instructions: 

```
mov     [ebp+UninitializedStackVariable.Value], eax
mov     [ebp+UninitializedStackVariable.Callback], offset _UninitializedStackVariableObjectCallback@0 ;UninitializedStackVariableObjectCallback()
```
This is interesting because you can see that there are two values being placed onto the stack, one from `eax` (which we already know would be `0xBAD0B0B0` in this code path) and one from this offset to the `UninitializedStackVariableObjectCallback` entity. You can right click that in IDA and change it to a hex value if you prefer, its the address of the `.Callback` function for this struct. So if we take this code path, two different variables are initialized with a value on the stack.

However, if we do NOT take this code path, we see we eventually do a `cmp [ebp+UninitializedStackVariable.Callback], edi` operation. When I stepped through this in WinDBG, this was making sure that the pointer to this `.Callback` function was not `NULL`. As long as it's not `NULL` (our `jz` fails, and we take the red code path), we will call the function. Since our function pointer was never initialized to `NULL` because we didn't provide the magic value, we will end up calling whatever this function pointer happens to be pointing to on the stack. After I right-click on the offset and change the value to hex we see:

![](/assets/images/AWE/uninit.PNG)

So it's going to call whatever is located at `ebp - 0x108`. That's really cool! What if we can get a pointer to shellcode at that address? That would require us to control a lot of values on the stack. Luckily, people way smarter than me have figured out how to do that via an API. 

As the [FuzzySec](https://www.fuzzysecurity.com/tutorials/expDev/17.html) and [j00ru](https://j00ru.vexillium.org/2011/05/windows-kernel-stack-spraying-techniques/) blogs point out, we can use [`NtMapUserPhyiscalPages`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapuserphysicalpages) to spray a pointer value onto the stack repeatedly. You can read j00ru's blog for a great breakdown of how the kernel stack works and is initialized and grows. 

Let's add a function to our code that will spray the stack with the values required to get shellcode executed. This part was tricky for me because I couldn't just import a header file with the `NtMapUserPhysicalPages` function prototype defined, I had to look at someone else's code for this part. I grabbed this from [tekwizz123's same exploit code](https://github.com/tekwizz123/HEVD-Exploit-Solutions/blob/master/HEVD-Unitialized-Stack-Variable/HEVD-Unitialized-Stack-Variable/HEVD-Unitialized-Stack-Variable.cpp). 

They defined the function with a `typedef`:
```cpp
typedef NTSTATUS(WINAPI* _NtMapUserPhysicalPages)(
	PINT BaseAddress,
	UINT32 NumberOfPages,
	PBYTE PageFrameNumbers);
```

Then they create an instance of the struct, then typecast the result of a `GetProcAddress` call grabbing a handle to `ntdll.dll` as the struct. Thanks for the help tekwizz123! Most of this code is literally just tekwizz's code, I was so helpless on this exploit, I could not get it working on my own.
```cpp
_NtMapUserPhysicalPages NtMapUserPhysicalPages = (_NtMapUserPhysicalPages) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapUserPhysicalPages");
```

Our code will be very similar. We can go ahead and basically finish our exploit from here. I will point out all the new code added and why. 

We obviously add the `typedef` to the beginning of our code. 

The most confusing part, will be this `PageFrameNumbers` parameter for our call to `NtMapUserPhysicalPages`. It takes a value of type `PBYTE`. We will satisfy this parameter as follows:
1. Create a Shellcode `char` buffer;
2. Create a RWX buffer the size of the Shellcode buffer with `VirtualAlloc`;
3. Copy the Shellcode `char` buffer into the RWX buffer with `memcopy`;
4. Create a pointer to the address of the RWX Shellcode buffer;
5. Create a `char` array the size of a `PINT` on our system (4) times `1024` (this is the max size the API allows you to call) which is `4096`;
6. Fill this newly created `4096` character long `char` array with this pointer to the address of the RWX Shellcode buffer;
7. Pass a `PBYTE` typcasted *by reference* value to the `char` array to `NtMapUserPhysicalPages`. 

Whew! That's quite a lot to take in, if you have to reread the code 100x, you are not alone. Thanks again to tekwizz123. 

The rest of the code is similar to previous exploits, we lifted the token stealing shellcode straight from b33f's aforementioned blogpost. We call `DeviceIoControl` the same way we have been in Python. The only difference from there is really the use of the `CreateProcessA` API which we used to just gloss over in Python by calling `popen()`. This simply starts a `cmd.exe` shell as `nt authority/system` at the tail end of our exploit when our token has been overwritten. If you want more information about this API, refer back to my Win32 shellcoding [posts](https://h0mbre.github.io/Win32_Reverse_Shellcode/#)!







