---
layout: post
title: "Fuzzing Like A Caveman 6: Binary Only Snapshot Fuzzing Harness"
date: 2022-04-02
classes: wide
header:
  teaser: /assets/images/avatar.jpg
tags:
  - fuzzing
  - harnessing
  - snapshot_fuzzing
---

## Introduction
It's been a while since I've done one of these, and one of my goals this year is to do more so here we are. A side project of mine is kind of reaching a good stopping point so I'll have more free-time to do my own research and blog again. Looking forward to sharing more and more this year. 

One of the most common questions that comes up in beginner fuzzing circles (of which I'm obviously a member) is how to harness a target so that it can be fuzzed in memory, as some would call in 'persistent' fashion, in order to gain performance. Persistent fuzzing has a niche use-case where the target doesn't touch much global state from fuzzcase to fuzzcase, an example would be a tight fuzzing loop for a single API in a library, or maybe a single function in a binary.

This style of fuzzing is faster than re-executing the target from scratch over and over as we bypass all the heavy syscalls/kernel routines associated with creating and destroying task structs. 

However, with binary targets for which we don't have source code, it's sometimes hard to discern what global state we're affecting while executing any code path without some heavy reverse engineering (disgusting, work? gross). Additionally, we often want to fuzz a wider loop. It doesn't do us much good to fuzz a function which returns a struct that is then never read or consumed in our fuzzing workflow. With these things in mind, we often find that 'snapshot' fuzzing would be a more robust workflow for binary targets, or even production binaries for which, we have source, but have gone through the sausage factory of enterprise build systems. 

So today, we're going to learn how to take an arbitrary binary only target that takes an input file from the user and turn it into a target that takes its input from memory instead and lends itself well to having its state reset between fuzzcases. 

## Target (Easy Mode)
For the purposes of this blogpost, we're going to harness objdump to be snapshot fuzzed. This will serve our purposes because it's relatively simple (single threaded, single process) and it's a common fuzzing target, especially as people do development work on their fuzzers. The point of this is not to impress you by sandboxing some insane target like Chrome, but to show beginners how to start thinking about harnessing. You want to lobotomize your targets so that they are unrecognizable to their original selves but retain the same semantics. You can get as creative as you want, and honestly, sometimes harnessing targets is some of the most satisfying work related to fuzzing. It feels great to successfully sandbox a target and have it play nice with your fuzzer. On to it then. 

## Hello World
The first step is to determine how we want to change objdump's behavior. Let's try running it under `strace` and disassemble `ls` and see how it behaves at the syscall level with `strace objdump -D /bin/ls`. What we're looking for is the point where `objdump` starts interacting with our input, `/bin/ls` in this case. In the output, if you scroll down past the boilerplate stuff, you can see the first appearance of `/bin/ls`: 
```
stat("/bin/ls", {st_mode=S_IFREG|0755, st_size=133792, ...}) = 0
stat("/bin/ls", {st_mode=S_IFREG|0755, st_size=133792, ...}) = 0
openat(AT_FDCWD, "/bin/ls", O_RDONLY)   = 3
fcntl(3, F_GETFD)                       = 0
fcntl(3, F_SETFD, FD_CLOEXEC)           = 0
```
 ***Keep in mind that as you read through this, if you're following along at home, your output might not match mine exactly. I'm likely on a different distribution than you running a different objdump than you. But the point of the blogpost is to just show concepts that you can be creative on your own.***

I also noticed that the program doesn't close our input file until the end of execution:
```
read(3, "\0\0\0\0\0\0\0\0\10\0\"\0\0\0\0\0\1\0\0\0\377\377\377\377\1\0\0\0\0\0\0\0"..., 4096) = 2720
write(1, ":(%rax)\n  21ffa4:\t00 00         "..., 4096) = 4096
write(1, "x0,%eax\n  220105:\t00 00         "..., 4096) = 4096
close(3)                                = 0
write(1, "023e:\t00 00                \tadd "..., 2190) = 2190
exit_group(0)                           = ?
+++ exited with 0 +++
```

This is good to know, we'll need our harness to be able to emulate an input file fairly well since objdump doesn't just read our file into a memory buffer in one shot or `mmap()` the input file. It is continuously reading from the file throughout the `strace` output. 

Since we don't have source code for the target, we're going to affect behavior by using an `LD_PRELOAD` shared object. By using an `LD_PRELOAD` shared object, we should be able to hook the wrapper functions around the syscalls that interact with our input file and change their behavior to suit our purposes. If you are unfamiliar with dynamic linking or `LD_PRELOAD`, this would be a good stopping point to go Google around for more information [great starting point](https://tbrindus.ca/correct-ld-preload-hooking-libc/). For starters, let's just get a *Hello, World!* shared object loaded. 

We can utilize `gcc` [Function Attributes](https://gcc.gnu.org/onlinedocs/gcc/Function-Attributes.html) to have our shared object execute code when it is loaded by the target by leveraging the `constructor` attribute. 

So our code so far will look like this:
```c
/* 
Compiler flags: 
gcc -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ldl
*/

#include <stdio.h> /* printf */

// Routine to be called when our shared object is loaded
__attribute__((constructor)) static void _hook_load(void) {
    printf("** LD_PRELOAD shared object loaded!\n");
}
```

I added the compiler flags needed to compile to the top of the file as a comment. I got these flags from this blogpost on using `LD_PRELOAD` shared objects a while ago: https://tbrindus.ca/correct-ld-preload-hooking-libc/.

We can now use the `LD_PRELOAD` environment variable and run objdump with our shared object which should print when loaded:
```
h0mbre@ubuntu:~/blogpost$ LD_PRELOAD=/home/h0mbre/blogpost/blog_harness.so objdump -D /bin/ls > /tmp/output.txt && head -n 20 /tmp/output.txt
**> LD_PRELOAD shared object loaded!

/bin/ls:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000238 <.interp>:
 238:   2f                      (bad)  
 239:   6c                      ins    BYTE PTR es:[rdi],dx
 23a:   69 62 36 34 2f 6c 64    imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
 241:   2d 6c 69 6e 75          sub    eax,0x756e696c
 246:   78 2d                   js     275 <_init@@Base-0x34e3>
 248:   78 38                   js     282 <_init@@Base-0x34d6>
 24a:   36 2d 36 34 2e 73       ss sub eax,0x732e3436
 250:   6f                      outs   dx,DWORD PTR ds:[rsi]
 251:   2e 32 00                xor    al,BYTE PTR cs:[rax]

Disassembly of section .note.ABI-tag:
```

It works, now we can start looking for functions to hook.

## Looking for Hooks
First thing we need to do, is create a fake file name to give objdump so that we can start testing things out. We will copy `/bin/ls` into the current working directory and call it `fuzzme`. This will allow us to generically play around with the harness for testing purposes. Now we have our `strace` output, we know that objdump calls `stat()` on the path for our input file (`/bin/ls`) a couple of times before we get that call to `openat()`. Since we know our file hasn't been opened yet, and the syscall uses the path for the first arg, we can guess that this syscall results from the libc exported wrapper function for `stat()` or `lstat()`. I'm going to assume `stat()` since we aren't dealing with any symbolic links for `/bin/ls` on my box. We can add a hook for `stat()` to test to see if we hit it and check if it's being called for our target input file (now changed to `fuzzme`).

In order to create a hook, we will follow a pattern where we define a pointer to the real function via a `typedef` and then we will initialize the pointer as `NULL`. Once we need to resolve the location of the **real** function we are hooking, we can use `dlsym(RLTD_NEXT, <symbol name>)` to get it's location and change the pointer value to the real symbol address. (This will be more clear later on). 

Now we need to hook `stat()` which appears as a `man 3` entry [here](https://linux.die.net/man/3/stat) (meaning it's a libc exported function) as well as a `man 2` entry (meaning it is a syscall). This was confusing to me for the longest time and I often misunderstood how syscalls actually worked because of this insistence on naming collisions. You can read one of the first research blogposts I ever did [here](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/) where the confusion is palpable and I often make erroneous claims. (PS, I'll never edit the old blogposts with errors in them, they are like time capsules, and it's kind of cool to me).

We want to write a function that when called, simply prints something and exits so that we know our hook was hit. For now, our code looks like this:
```c
/* 
Compiler flags: 
gcc -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ldl
*/

#include <stdio.h> /* printf */
#include <sys/stat.h> /* stat */
#include <stdlib.h> /* exit */

// Filename of the input file we're trying to emulate
#define FUZZ_TARGET "fuzzme"

// Declare a prototype for the real stat as a function pointer
typedef int (*stat_t)(const char *restrict path, struct stat *restrict buf);
stat_t real_stat = NULL;

// Hook function, objdump will call this stat instead of the real one
int stat(const char *restrict path, struct stat *restrict buf) {
    printf("** stat() hook!\n");
    exit(0);
}

// Routine to be called when our shared object is loaded
__attribute__((constructor)) static void _hook_load(void) {
    printf("** LD_PRELOAD shared object loaded!\n");
}
```

However, if we compile and run that, we don't ever print and exit so our hook is not being called. Something is going wrong. Sometimes, file related functions in libc have `64` variants, such as `open()` and `open64()` that are used somewhat interchangably depending on configurations and flags. I tried hooking a `stat64()` but still had no luck with the hook being reached. 

Luckily, I'm not the first person with this problem, there is a [great answer on Stackoverflow about the very issue](https://stackoverflow.com/questions/5478780/c-and-ld-preload-open-and-open64-calls-intercepted-but-not-stat64) that describes how libc doesn't actually export `stat()` the same way it does for other functions like `open()` and `open64()`, instead it exports a symbol called `__xstat()` which has a slightly different signature and requires a new argument called `version` which is meant to describe which version of `stat struct` the caller is expecting. This is supposed to all happen magically under the hood but that's where we live now, so we have to make the magic happen ourselves. The same rules apply for `lstat()` and `fstat()` as well, they have `__lxstat()` and `__fxstat()` respectively.

I found the definitions for the functions [here](https://refspecs.linuxfoundation.org/LSB_1.1.0/gLSB/baselib-xstat-1.html). So we can add the `__xstat()` hook to our shared object in place of the `stat()` and see if our luck changes. Our code now looks like this:
```c
/* 
Compiler flags: 
gcc -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ldl
*/

#include <stdio.h> /* printf */
#include <sys/stat.h> /* stat */
#include <stdlib.h> /* exit */
#include <unistd.h> /* __xstat, __fxstat */

// Filename of the input file we're trying to emulate
#define FUZZ_TARGET "fuzzme"

// Declare a prototype for the real stat as a function pointer
typedef int (*__xstat_t)(int __ver, const char *__filename, struct stat *__stat_buf);
__xstat_t real_xstat = NULL;

// Hook function, objdump will call this stat instead of the real one
int __xstat(int __ver, const char *__filename, struct stat *__stat_buf) {
    printf("** Hit our __xstat() hook!\n");
    exit(0);
}

// Routine to be called when our shared object is loaded
__attribute__((constructor)) static void _hook_load(void) {
    printf("** LD_PRELOAD shared object loaded!\n");
}
```

Now if we run our shared object, we get the desired outcome, somewhere, our hook is hit. Now we can help ourselves out a bit and print the filenames being requested by the hook and then actually call the real `__xstat()` on behalf of the caller. Now when our hook is hit, we will have to resolve the location of the real `__xstat()` by name, so we'll add a symbol resolving function to our shared object. Our shared object code now looks like this:
```c
/* 
Compiler flags: 
gcc -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ldl
*/

#define _GNU_SOURCE     /* dlsym */
#include <stdio.h> /* printf */
#include <sys/stat.h> /* stat */
#include <stdlib.h> /* exit */
#include <unistd.h> /* __xstat, __fxstat */
#include <dlfcn.h> /* dlsym and friends */

// Filename of the input file we're trying to emulate
#define FUZZ_TARGET "fuzzme"

// Declare a prototype for the real stat as a function pointer
typedef int (*__xstat_t)(int __ver, const char *__filename, struct stat *__stat_buf);
__xstat_t real_xstat = NULL;

// Returns memory address of *next* location of symbol in library search order
static void *_resolve_symbol(const char *symbol) {
    // Clear previous errors
    dlerror();

    // Get symbol address
    void* addr = dlsym(RTLD_NEXT, symbol);

    // Check for error
    char* err = NULL;
    err = dlerror();
    if (err) {
        addr = NULL;
        printf("Err resolving '%s' addr: %s\n", symbol, err);
        exit(-1);
    }
    
    return addr;
}

// Hook function, objdump will call this stat instead of the real one
int __xstat(int __ver, const char *__filename, struct stat *__stat_buf) {
    // Print the filename requested
    printf("** __xstat() hook called for filename: '%s'\n", __filename);

    // Resolve the address of the real __xstat() on demand and only once
    if (!real_xstat) {
        real_xstat = _resolve_symbol("__xstat");
    }

    // Call the real __xstat() for the caller so everything keeps going
    return real_xstat(__ver, __filename, __stat_buf);
}

// Routine to be called when our shared object is loaded
__attribute__((constructor)) static void _hook_load(void) {
    printf("** LD_PRELOAD shared object loaded!\n");
}
```

Ok so now when we run this, and we check for our print statements, things get a little spicy. 
```
h0mbre@ubuntu:~/blogpost$ LD_PRELOAD=/home/h0mbre/blogpost/blog_harness.so objdump -D fuzzme > /tmp/output.txt && grep "** __xstat" /tmp/output.txt
** __xstat() hook called for filename: 'fuzzme'
** __xstat() hook called for filename: 'fuzzme'
```

So now we can have some fun. 

## __xstat() Hook

So the purpose of this hook will be to lie to objdump and make it think it successfully `stat()` the input file. Remember, we're making a snapshot fuzzing harness so our objective is to constantly be creating new inputs and feeding them to objdump through this harness. Most importantly, our harness will need to be able to represent our variable length inputs (which will be stored purely in memory) as files. Each fuzzcase, the file length can change and our harness needs to accomodate that.

My idea at this point was to create a somewhat "legit" `stat struct` that would normally be returned for our actual file `fuzzme` which is just a copy of `/bin/ls`. We can store this `stat struct` globally and only update the size field as each new fuzz case comes through. So the timeline of our snapshot fuzzing workflow would look something like:
1. Our `constructor` function is called when our shared object is loaded
2. Our `constructor` sets up a global "legit" `stat struct` that we can update for each fuzzcase and pass back to callers of `__xstat()` trying to `stat()` our fuzzing target
3. The imaginary fuzzer runs objdump to the snapshot location
4. Our `__xstat()` hook updates the the global "legit" `stat struct` size field and copies the `stat struct` into the caller's buffer
5. The imaginary fuzzer restores the state of objdump to its state at snapshot time
6. The imaginary fuzzer copies a new input into harness and updates the input size
7. Our `__xstat()` hook is called once again, and we repeat step 4, this process occurs over and over forever. 

So we're imagining the fuzzer has some routine like this in pseudocode, even though it'd likely be cross-process and require `process_vm_writev`:
```
insert_fuzzcase(config.input_location, config.input_size_location, input, input_size) {
  memcpy(config.input_location, &input, input_size);
  memcpy(config.input_size_location, &input_size, sizeof(size_t));
}
```

One important thing to keep in mind is that if the snapshot fuzzer is restoring objdump to its snapshot state every fuzzing iteration, we must be careful not to depend on any global mutable memory. The global `stat struct` will be safe since it will be instantiated during the `constructor` however, its size-field will be restored to its original value each fuzzing iteration by the fuzzer's snapshot restore routine. 

We will also need a global, recognizable address to store variable mutable global data like the current input's size. Several snapshot fuzzers have the flexibility to ignore contiguous ranges of memory for restoration purposes. So if we're able to create some contiguous buffers in memory at recognizable addresses, we can have our imaginary fuzzer ignore those ranges for snapshot restorations. So we need to have a place to store the inputs, as well as information about their size. We would then somehow tell the fuzzer about these locations and when it generated a new input, it would copy it into the input location and then update the current input size information.

So now our constructor has an additional job: setup the input location as well as the input size information. We can do this easily with a call to `mmap()` which will allow us to specify an address we want our mapping mapped to with the `MAP_FIXED` flag. We'll also create a `MAX_INPUT_SZ` definition so that we know how much memory to map from the input location. 

Just by themselves, the functions related to mapping memory space for the inputs themselves and their size information looks like this. Notice that we use `MAP_FIXED` and we check the returned address from `mmap()` just to make sure the call didn't succeed but map our memory at a different location:
```c
// Map memory to hold our inputs in memory and information about their size
static void _create_mem_mappings(void) {
    void *result = NULL;

    // Map the page to hold the input size
    result = mmap(
        (void *)(INPUT_SZ_ADDR),
        sizeof(size_t),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_SZ_ADDR)) {
        printf("Err mapping INPUT_SZ_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Let's actually initialize the value at the input size location as well
    *(size_t *)INPUT_SZ_ADDR = 0;

    // Map the pages to hold the input contents
    result = mmap(
        (void *)(INPUT_ADDR),
        (size_t)(MAX_INPUT_SZ),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_ADDR)) {
        printf("Err mapping INPUT_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Init the value
    memset((void *)INPUT_ADDR, 0, (size_t)MAX_INPUT_SZ);
}
```

`mmap()` will actually map multiples of whatever the page size is on your system (typically 4096 bytes). So, when we ask for `sizeof(size_t)` bytes for the mapping, `mmap()` is like: "Hmm, that's just a page dude" and gives us back a whole page from `0x1336000 - 0x1337000` not inclusive on the high-end. 

**Random sidenote, be careful about arithmetic in definitions and macros as I've done here with `MAX_INPUT_SIZE`, it's very easy for the pre-processor to substitute your text for the definition keyword and ruin some order of operations or even overflow a specific primitive type like `int`.**

Now that we have memory set up for the fuzzer to store inputs and information about the input's size, we can create that global stat struct. But we actually have a big problem. How can we call into `__xstat()` to get our "legit" `stat struct` if we have `__xstat()` hooked? We would hit our own hook. To circumvent this, we can call `__xstat()` with a special `__ver` argument that we know will mean that it was called from our `constructor`, the variable is an `int` so let's go with `0x1337` as the special value. That way, in our hook, if we check `__ver` and it's `0x1337`, we know we are being called from the `constructor` and we can actually stat our real file and create a global "legit" `stat struct`. When I dumped a normal call by objdump to `__xstat()` the `__version` was always a value of `1` so we will patch it back to that inside our hook. Now our entire shared object source file should look like this:
```c
/* 
Compiler flags: 
gcc -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ldl
*/

#define _GNU_SOURCE     /* dlsym */
#include <stdio.h> /* printf */
#include <sys/stat.h> /* stat */
#include <stdlib.h> /* exit */
#include <unistd.h> /* __xstat, __fxstat */
#include <dlfcn.h> /* dlsym and friends */
#include <sys/mman.h> /* mmap */
#include <string.h> /* memset */

// Filename of the input file we're trying to emulate
#define FUZZ_TARGET "fuzzme"

// Definitions for our in-memory inputs 
#define INPUT_SZ_ADDR   0x1336000
#define INPUT_ADDR      0x1337000
#define MAX_INPUT_SZ    (1024 * 1024)

// Our "legit" global stat struct
struct stat st;

// Declare a prototype for the real stat as a function pointer
typedef int (*__xstat_t)(int __ver, const char *__filename, struct stat *__stat_buf);
__xstat_t real_xstat = NULL;

// Returns memory address of *next* location of symbol in library search order
static void *_resolve_symbol(const char *symbol) {
    // Clear previous errors
    dlerror();

    // Get symbol address
    void* addr = dlsym(RTLD_NEXT, symbol);

    // Check for error
    char* err = NULL;
    err = dlerror();
    if (err) {
        addr = NULL;
        printf("Err resolving '%s' addr: %s\n", symbol, err);
        exit(-1);
    }
    
    return addr;
}

// Hook for __xstat 
int __xstat(int __ver, const char* __filename, struct stat* __stat_buf) {
    // Resolve the real __xstat() on demand and maybe multiple times!
    if (NULL == real_xstat) {
        real_xstat = _resolve_symbol("__xstat");
    }

    // Assume the worst, always
    int ret = -1;

    // Special __ver value check to see if we're calling from constructor
    if (0x1337 == __ver) {
        // Patch back up the version value before sending to real xstat
        __ver = 1;

        ret = real_xstat(__ver, __filename, __stat_buf);

        // Set the real_xstat back to NULL
        real_xstat = NULL;
        return ret;
    }

    // Determine if we're stat'ing our fuzzing target
    if (!strcmp(__filename, FUZZ_TARGET)) {
        // Update our global stat struct
        st.st_size = *(size_t *)INPUT_SZ_ADDR;

        // Send it back to the caller, skip syscall
        memcpy(__stat_buf, &st, sizeof(struct stat));
        ret = 0;
    }

    // Just a normal stat, send to real xstat
    else {
        ret = real_xstat(__ver, __filename, __stat_buf);
    }

    return ret;
}

// Map memory to hold our inputs in memory and information about their size
static void _create_mem_mappings(void) {
    void *result = NULL;

    // Map the page to hold the input size
    result = mmap(
        (void *)(INPUT_SZ_ADDR),
        sizeof(size_t),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_SZ_ADDR)) {
        printf("Err mapping INPUT_SZ_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Let's actually initialize the value at the input size location as well
    *(size_t *)INPUT_SZ_ADDR = 0;

    // Map the pages to hold the input contents
    result = mmap(
        (void *)(INPUT_ADDR),
        (size_t)(MAX_INPUT_SZ),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_ADDR)) {
        printf("Err mapping INPUT_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Init the value
    memset((void *)INPUT_ADDR, 0, (size_t)MAX_INPUT_SZ);
}

// Routine to be called when our shared object is loaded
__attribute__((constructor)) static void _hook_load(void) {
    // Create memory mappings to hold our input and information about its size
    _create_mem_mappings();    
}
```

Now if we run this, we get the following output: 
```
h0mbre@ubuntu:~/blogpost$ LD_PRELOAD=/home/h0mbre/blogpost/blog_harness.so objdump -D fuzzme
objdump: Warning: 'fuzzme' is not an ordinary file
```

This is cool, this means that the objdump devs did something right and their `stat()` would say: "Hey, this file is zero bytes in length, something weird is going on" and they spit out this error message and exit. Good job devs!

So we have identified a problem, we need to **simulate** the fuzzer placing a real input into memory, to do that, I'm going to start using `#ifdef` to define whether or not we're testing our shared object. So basically, if we compile the shared object and define `TEST`, our shared object will copy an "input" into memory to simulate how the fuzzer would behave during fuzzing and we can see if our harness is working appropriately. So if we define `TEST`, we will copy `/bin/ed` into memory, and we will update our global "legit" `stat struct` size member, and place the `/bin/ed` bytes into memory. 

You can compile the shared object now to perform the test as follows:
```
gcc -D TEST -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ld
```

We also need to set up our global "legit" `stat struct`, the code to do that should look as follows. Remember, we pass a fake `__ver` variable to let the `__xstat()` hook know that it's us in the `constructor` routine, which allows the hook to behave well and give us the `stat struct` we need:
```c
// Create a "legit" stat struct globally to pass to callers
static void _setup_stat_struct(void) {
    // Create a global stat struct for our file in case someone asks, this way
    // when someone calls stat() or fstat() on our target, we can just return the
    // slightly altered (new size) stat struct &skip the kernel, save syscalls
    int result = __xstat(0x1337, FUZZ_TARGET, &st);
    if (-1 == result) {
        printf("Error creating stat struct for '%s' during load\n", FUZZ_TARGET);
    }
}
```

All in all, our entire harness looks like this now:
```c
/* 
Compiler flags: 
gcc -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ldl
*/

#define _GNU_SOURCE     /* dlsym */
#include <stdio.h> /* printf */
#include <sys/stat.h> /* stat */
#include <stdlib.h> /* exit */
#include <unistd.h> /* __xstat, __fxstat */
#include <dlfcn.h> /* dlsym and friends */
#include <sys/mman.h> /* mmap */
#include <string.h> /* memset */
#include <fcntl.h> /* open */

// Filename of the input file we're trying to emulate
#define FUZZ_TARGET     "fuzzme"

// Definitions for our in-memory inputs 
#define INPUT_SZ_ADDR   0x1336000
#define INPUT_ADDR      0x1337000
#define MAX_INPUT_SZ    (1024 * 1024)

// For testing purposes, we read /bin/ed into our input buffer to simulate
// what the fuzzer would do
#define  TEST_FILE      "/bin/ed"

// Our "legit" global stat struct
struct stat st;

// Declare a prototype for the real stat as a function pointer
typedef int (*__xstat_t)(int __ver, const char *__filename, struct stat *__stat_buf);
__xstat_t real_xstat = NULL;

// Returns memory address of *next* location of symbol in library search order
static void *_resolve_symbol(const char *symbol) {
    // Clear previous errors
    dlerror();

    // Get symbol address
    void* addr = dlsym(RTLD_NEXT, symbol);

    // Check for error
    char* err = NULL;
    err = dlerror();
    if (err) {
        addr = NULL;
        printf("Err resolving '%s' addr: %s\n", symbol, err);
        exit(-1);
    }
    
    return addr;
}

// Hook for __xstat 
int __xstat(int __ver, const char* __filename, struct stat* __stat_buf) {
    // Resolve the real __xstat() on demand and maybe multiple times!
    if (!real_xstat) {
        real_xstat = _resolve_symbol("__xstat");
    }

    // Assume the worst, always
    int ret = -1;

    // Special __ver value check to see if we're calling from constructor
    if (0x1337 == __ver) {
        // Patch back up the version value before sending to real xstat
        __ver = 1;

        ret = real_xstat(__ver, __filename, __stat_buf);

        // Set the real_xstat back to NULL
        real_xstat = NULL;
        return ret;
    }

    // Determine if we're stat'ing our fuzzing target
    if (!strcmp(__filename, FUZZ_TARGET)) {
        // Update our global stat struct
        st.st_size = *(size_t *)INPUT_SZ_ADDR;

        // Send it back to the caller, skip syscall
        memcpy(__stat_buf, &st, sizeof(struct stat));
        ret = 0;
    }

    // Just a normal stat, send to real xstat
    else {
        ret = real_xstat(__ver, __filename, __stat_buf);
    }

    return ret;
}

// Map memory to hold our inputs in memory and information about their size
static void _create_mem_mappings(void) {
    void *result = NULL;

    // Map the page to hold the input size
    result = mmap(
        (void *)(INPUT_SZ_ADDR),
        sizeof(size_t),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_SZ_ADDR)) {
        printf("Err mapping INPUT_SZ_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Let's actually initialize the value at the input size location as well
    *(size_t *)INPUT_SZ_ADDR = 0;

    // Map the pages to hold the input contents
    result = mmap(
        (void *)(INPUT_ADDR),
        (size_t)(MAX_INPUT_SZ),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_ADDR)) {
        printf("Err mapping INPUT_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Init the value
    memset((void *)INPUT_ADDR, 0, (size_t)MAX_INPUT_SZ);
}

// Create a "legit" stat struct globally to pass to callers
static void _setup_stat_struct(void) {
    int result = __xstat(0x1337, FUZZ_TARGET, &st);
    if (-1 == result) {
        printf("Error creating stat struct for '%s' during load\n", FUZZ_TARGET);
    }
}

// Used for testing, load /bin/ed into the input buffer and update its size info
#ifdef TEST
static void _test_func(void) {    
    // Open TEST_FILE for reading
    int fd = open(TEST_FILE, O_RDONLY);
    if (-1 == fd) {
        printf("Failed to open '%s' during test\n", TEST_FILE);
        exit(-1);
    }

    // Attempt to read max input buf size
    ssize_t bytes = read(fd, (void*)INPUT_ADDR, (size_t)MAX_INPUT_SZ);
    close(fd);

    // Update the input size
    *(size_t *)INPUT_SZ_ADDR = (size_t)bytes;
}
#endif

// Routine to be called when our shared object is loaded
__attribute__((constructor)) static void _hook_load(void) {
    // Create memory mappings to hold our input and information about its size
    _create_mem_mappings();

    // Setup global "legit" stat struct
    _setup_stat_struct();

    // If we're testing, load /bin/ed up into our input buffer and update size
#ifdef TEST
    _test_func();
#endif
}
```

Now if we run this under `strace`, we notice that our two `stat()` calls are conspicuously missing.
```
close(3)                                = 0
openat(AT_FDCWD, "fuzzme", O_RDONLY)    = 3
fcntl(3, F_GETFD)                       = 0
fcntl(3, F_SETFD, FD_CLOEXEC)           = 0
```

We no longer see the `stat()` calls before the `openat()` and the program does not break in any significant way. So this hook seems to be working appropriately. We now need to handle the `openat()` and make sure we don't actually interact with our input file, but instead trick objdump to interact with our input in memory.

## Finding a Way to Hook `openat()`
My non-expert intuition tells me theres probably a few ways in which a libc function could end up calling `openat()` under the hood. Those ways might include the wrappers `open()` as well as `fopen()`. We also need to be mindful of their `64` variants as well (`open64()`, `fopen64()`). I decided to try the `fopen()` hooks first:
```c
// Declare prototype for the real fopen and its friend fopen64 
typedef FILE* (*fopen_t)(const char* pathname, const char* mode);
fopen_t real_fopen = NULL;

typedef FILE* (*fopen64_t)(const char* pathname, const char* mode);
fopen64_t real_fopen64 = NULL;

...

// Exploratory hooks to see if we're using fopen() related functions to open
// our input file
FILE* fopen(const char* pathname, const char* mode) {
    printf("** fopen() called for '%s'\n", pathname);
    exit(0);
}

FILE* fopen64(const char* pathname, const char* mode) {
    printf("** fopen64() called for '%s'\n", pathname);
    exit(0);
}
```

If we compile and run our exploratory hooks, we get the following output:
```
h0mbre@ubuntu:~/blogpost$ LD_PRELOAD=/home/h0mbre/blogpost/blog_harness.so objdump -D fuzzme
** fopen64() called for 'fuzzme'
```

Bingo, dino DNA. 

So now we can flesh that hooked function out a bit to behave how we want. 

## Refining an `fopen64()` Hook
The definition for `fopen64()` is: ` FILE *fopen(const char *restrict pathname, const char *restrict mode);`. The returned `FILE *` poses a slight problem to us because this is an opaque data structure that is not meant to be understood by the caller. Which is to say, the caller is not meant to access any members of this data structure or worry about its layout in any way. You're just supposed to use the returned `FILE *` as an object to pass to other functions, such as `fclose()`. The system deals with the data structure there in those types of related functions so that programmers don't have to worry about a specific implementation.

We don't actually know how the returned `FILE *` will be used, it may not be used at all, or it may be passed to a function such as `fread()` so we need a way to return a convincing `FILE *` data structure to the caller that is actually built from our input in memory and NOT from the input file. Luckily, there is a libc function called `fmemopen()` which behaves very similarly to `fopen()` and also returns a `FILE *`. So we can go ahead and create a `FILE *` to return to callers of `fopen64()` with `fuzzme` as the target input file. Shoutout to @domenuk for showing me `fmemopen()`, I had never come across it before.

There is one key difference though. `fopen()` will actually obtain file descriptor for the underlying file and `fmemopen()`, since it is not actually openining a file, will not. So somewhere in the `FILE *` data structure, there is a file descriptor for the underlying file if returned from `fopen()` and there isn't one if returned from `fmemopen()`. This is very important as functions such as `int fileno(FILE *stream)` can parse a `FILE *` and return its underlying file descriptor to the caller. Objdump may want to do this for some reason and we need to be able to robustly handle it. So we need a way to know if someone is trying to use our faked `FILE *` underlying file descriptor.

My idea for this was to simply find the struct member containing the file descriptor in the `FILE *` returned from `fmemopen()` and change it to be something ridiculous like `1337` so that if objdump ever tried to use that file descriptor we would know the source of it and could try to hook any interactions with the file descriptor. So now our `fopen64()` hook should look as follows:
```c
// Our fopen hook, return a FILE* to the caller, also, if we are opening our
// target make sure we're not able to write to the file
FILE* fopen64(const char* pathname, const char* mode) {
    // Resolve symbol on demand and only once
    if (NULL == real_fopen64) {
        real_fopen64 = _resolve_symbol("fopen64");
    }

    // Check to see what file we're opening
    FILE* ret = NULL;
    if (!strcmp(FUZZ_TARGET, pathname)) {
        // We're trying to open our file, make sure it's a read-only mode
        if (strcmp(mode, "r")) {
            printf("Attempt to open fuzz-target in illegal mode: '%s'\n", mode);
            exit(-1);
        }

        // Open shared memory FILE* and return to caller
        ret = fmemopen((void*)INPUT_ADDR, *(size_t*)INPUT_SZ_ADDR, mode);
        
        // Make sure we've never fopen()'d our fuzzing target before
        if (faked_fp) {
            printf("Attempting to fopen64() fuzzing target more than once\n");
            exit(-1);
        }

        // Update faked_fp
        faked_fp = ret;

        // Change the filedes to something we know
        ret->_fileno = 1337;
    }

    // We're not opening our file, send to regular fopen
    else {
        ret = real_fopen64(pathname, mode);
    }

    // Return FILE stream ptr to caller
    return ret;
}
```

You can see we:
1. Resolve the symbol location if it hasn't been yet
2. Check to see if we're being called on our fuzzing target input file
3. Call `fmemopen()` and open the memory buffer where our current input is in memory along with the input's size

You may also notice a few safety checks as well to make sure things don't go unnoticed. We have a global variable that is `FILE *faked_fp` that we initialize to `NULL` which let's us know if we've ever opened our input more than once (it wouldn't be `NULL` anymore on subsequent attempts to open it). 

We also do a check on the `mode` argument to make sure we're getting a read-only `FILE *` back. We don't want objdump to alter our input or write to it in any way and if it tries to, we need to know about it.

Running our shared object at this point nets us the following output:
```
h0mbre@ubuntu:~/blogpost$ LD_PRELOAD=/home/h0mbre/blogpost/blog_harness.so objdump -D fuzzme
objdump: fuzzme: Bad file descriptor
```

My spidey-sense is telling me something tried to interact with a file descriptor of `1337`. Let's run again under `strace` and see what happens.
```
h0mbre@ubuntu:~/blogpost$ strace -E LD_PRELOAD=/home/h0mbre/blogpost/blog_harness.so objdump -D fuzzme > /tmp/output.txt
```

In the output, we can see some syscalls to `fcntl()` and `fstat()` both being called with a file descriptor of `1337` which obviously doesn't exist in our objdump process, so we've been able to find the problem.
```
fcntl(1337, F_GETFD)                    = -1 EBADF (Bad file descriptor)
prlimit64(0, RLIMIT_NOFILE, NULL, {rlim_cur=4*1024, rlim_max=4*1024}) = 0
fstat(1337, 0x7fff4bf54c90)             = -1 EBADF (Bad file descriptor)
fstat(1337, 0x7fff4bf54bf0)             = -1 EBADF (Bad file descriptor)
```

As we've already learned, there is no direct export in libc for `fstat()`, it's one of those weird ones like `stat()` and we actually have to hook `__fxstat()`. So let's try and hook that to see if it gets called for our `1337` file descriptor. The hook function will look like this to start:
```c
// Declare prototype for the real __fxstat
typedef int (*__fxstat_t)(int __ver, int __filedesc, struct stat *__stat_buf);
__fxstat_t real_fxstat = NULL;

...

// Hook for __fxstat
int __fxstat (int __ver, int __filedesc, struct stat *__stat_buf) {
    printf("** __fxstat() called for __filedesc: %d\n", __filedesc);
    exit(0);
}
```

Now we also still have that `fcntl()` to deal with, luckily that hook is straightforward, if someone asks for the `F_GETFD` aka, the flags associated with that special `1337` file descriptor, we'll simply return `O_RDONLY` as those were the flags it was "opened" with, and we'll just panic for now if someone calls it for a different file descriptor. This hook looks like this:
```c
// Declare prototype for the real __fcntl
typedef int (*fcntl_t)(int fildes, int cmd, ...);
fcntl_t real_fcntl = NULL;

...

// Hook for fcntl
int fcntl(int fildes, int cmd, ...) {
    // Resolve fcntl symbol if needed
    if (NULL == real_fcntl) {
        real_fcntl = _resolve_symbol("fcntl");
    }

    if (fildes == 1337) {
        return O_RDONLY;
    }

    else {
        printf("** fcntl() called for real file descriptor\n");
        exit(0);
    }
}
```

Running this under `strace` now, the `fcntl()` call is absent as we would expect:
```
openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=26376, ...}) = 0
mmap(NULL, 26376, PROT_READ, MAP_SHARED, 3, 0) = 0x7ff61d331000
close(3)                                = 0
prlimit64(0, RLIMIT_NOFILE, NULL, {rlim_cur=4*1024, rlim_max=4*1024}) = 0
fstat(1, {st_mode=S_IFREG|0664, st_size=0, ...}) = 0
write(1, "** __fxstat() called for __filed"..., 42) = 42
exit_group(0)                           = ?
+++ exited with 0 +++
```

Now we can flesh out our `__fxstat()` hook with some logic. The caller is hoping to retrieve a `stat struct` from the function for our fuzzing target `fuzzme` by passing the special file descriptor `1337`. Luckily, we have our global `stat struct` that we can return after we update its size to match that of the current input in memory (as tracked by us and the fuzzer as the value at `INPUT_SIZE_ADDR`). So if called, we simply update our `stat struct` size, and `memcpy` our struct into their `*__stat_buf`. Our complete hook now looks like this:
```c
// Hook for __fxstat
int __fxstat (int __ver, int __filedesc, struct stat *__stat_buf) {
    // Resolve the real fxstat
    if (NULL == real_fxstat) {
        real_fxstat = _resolve_symbol("__fxstat");
    }

    int ret = -1;

    // Check to see if we're stat'ing our fuzz target
    if (1337 == __filedesc) {
        // Patch the global struct with current input size
        st.st_size = *(size_t*)INPUT_SZ_ADDR;

        // Copy global stat struct back to caller
        memcpy(__stat_buf, &st, sizeof(struct stat));
        ret = 0;
    }

    // Normal stat, send to real fxstat
    else {
        ret = real_fxstat(__ver, __filedesc, __stat_buf);
    }

    return ret;
}
```

Now if we run this, we actually don't break and objdump is able exit cleanly under `strace`.

## Wrapping Up
To test whether or not we have done a fair job, we will go ahead and output `objdump -D fuzzme` to a file, and then we'll go ahead and output the same command but with our harness shared object loaded. Lastly, we'll run `objdump -D /bin/ed` and output to a file to see if our harness created the same output.
```
h0mbre@ubuntu:~/blogpost$ objdump -D fuzzme > /tmp/fuzzme_original.txt      
h0mbre@ubuntu:~/blogpost$ LD_PRELOAD=/home/h0mbre/blogpost/blog_harness.so objdump -D fuzzme > /tmp/harness.txt 
h0mbre@ubuntu:~/blogpost$ objdump -D /bin/ed > /tmp/ed.txt
```

Then we `sha1sum` the files:
```
h0mbre@ubuntu:~/blogpost$ sha1sum /tmp/fuzzme_original.txt /tmp/harness.txt /tmp/ed.txt 
938518c86301ab00ddf6a3ef528d7610fa3fd05a  /tmp/fuzzme_original.txt
add4e6c3c298733f48fbfe143caee79445c2f196  /tmp/harness.txt
10454308b672022b40f6ce5e32a6217612b462c8  /tmp/ed.txt
```

We actually get three different hashes, we wanted the harness and `/bin/ed` to output the same output since `/bin/ed` is the input we loaded into memory.
```
h0mbre@ubuntu:~/blogpost$ ls -laht /tmp
total 14M
drwxrwxrwt 28 root   root   128K Apr  3 08:44 .
-rw-rw-r--  1 h0mbre h0mbre 736K Apr  3 08:43 ed.txt
-rw-rw-r--  1 h0mbre h0mbre 736K Apr  3 08:43 harness.txt
-rw-rw-r--  1 h0mbre h0mbre 2.2M Apr  3 08:42 fuzzme_original.txt
```

Ah, they are the same length at least, that must mean there is a subtle difference and `diff` shows us why the hashes aren't the same:
```
h0mbre@ubuntu:~/blogpost$ diff /tmp/ed.txt /tmp/harness.txt 
2c2
< /bin/ed:     file format elf64-x86-64
---
> fuzzme:     file format elf64-x86-64
```

The name of the file in the `argv[]` array is different, so that's the only difference. In the end we were able to feed objdump an input file, but have it actually take input from an in-memory buffer in our harness. 

One more thing, we actually forgot that objdump closes our file didn't we! So I went ahead and added a quick `fclose()` hook. We wouldn't have any problems if `fclose()` just wanted to free the heap memory associated with our `fmemopen()` returned `FILE *`; however, it would also probably try to call `close()` on that wonky file descriptor as well and we don't want that. It might not even matter in the end, just want to be safe. Up to the reader to experiment and see what changes. The imaginary fuzzer should restore `FILE *` heap memory anyways during its snapshot restoration routine.

## Conclusion
There are a million different ways to accomplish this goal, I just wanted to walk you through my thought process. There are actually a lot of cool things you can do with this harness, one thing I've done is actually hook `malloc()` to fail on large allocations so that I don't waste fuzzing cycles on things that will eventually timeout. You can also create an `at_exit()` choke point so that no matter what, the program executes your `at_exit()` function every time it is exiting which can be useful for snapshot resets if the program can take multiple exit paths as you only have to cover the one exit point. 

Hopefully this was useful to some! The complete code to the harness is below, happy fuzzing!
```c
/* 
Compiler flags: 
gcc -shared -Wall -Werror -fPIC blog_harness.c -o blog_harness.so -ldl
*/

#define _GNU_SOURCE     /* dlsym */
#include <stdio.h> /* printf */
#include <sys/stat.h> /* stat */
#include <stdlib.h> /* exit */
#include <unistd.h> /* __xstat, __fxstat */
#include <dlfcn.h> /* dlsym and friends */
#include <sys/mman.h> /* mmap */
#include <string.h> /* memset */
#include <fcntl.h> /* open */

// Filename of the input file we're trying to emulate
#define FUZZ_TARGET     "fuzzme"

// Definitions for our in-memory inputs 
#define INPUT_SZ_ADDR   0x1336000
#define INPUT_ADDR      0x1337000
#define MAX_INPUT_SZ    (1024 * 1024)

// For testing purposes, we read /bin/ed into our input buffer to simulate
// what the fuzzer would do
#define  TEST_FILE      "/bin/ed"

// Our "legit" global stat struct
struct stat st;

// FILE * returned to callers of fopen64() 
FILE *faked_fp = NULL;

// Declare a prototype for the real stat as a function pointer
typedef int (*__xstat_t)(int __ver, const char *__filename, struct stat *__stat_buf);
__xstat_t real_xstat = NULL;

// Declare prototype for the real fopen and its friend fopen64 
typedef FILE* (*fopen_t)(const char* pathname, const char* mode);
fopen_t real_fopen = NULL;

typedef FILE* (*fopen64_t)(const char* pathname, const char* mode);
fopen64_t real_fopen64 = NULL;

// Declare prototype for the real __fxstat
typedef int (*__fxstat_t)(int __ver, int __filedesc, struct stat *__stat_buf);
__fxstat_t real_fxstat = NULL;

// Declare prototype for the real __fcntl
typedef int (*fcntl_t)(int fildes, int cmd, ...);
fcntl_t real_fcntl = NULL;

// Returns memory address of *next* location of symbol in library search order
static void *_resolve_symbol(const char *symbol) {
    // Clear previous errors
    dlerror();

    // Get symbol address
    void* addr = dlsym(RTLD_NEXT, symbol);

    // Check for error
    char* err = NULL;
    err = dlerror();
    if (err) {
        addr = NULL;
        printf("** Err resolving '%s' addr: %s\n", symbol, err);
        exit(-1);
    }
    
    return addr;
}

// Hook for __xstat 
int __xstat(int __ver, const char* __filename, struct stat* __stat_buf) {
    // Resolve the real __xstat() on demand and maybe multiple times!
    if (!real_xstat) {
        real_xstat = _resolve_symbol("__xstat");
    }

    // Assume the worst, always
    int ret = -1;

    // Special __ver value check to see if we're calling from constructor
    if (0x1337 == __ver) {
        // Patch back up the version value before sending to real xstat
        __ver = 1;

        ret = real_xstat(__ver, __filename, __stat_buf);

        // Set the real_xstat back to NULL
        real_xstat = NULL;
        return ret;
    }

    // Determine if we're stat'ing our fuzzing target
    if (!strcmp(__filename, FUZZ_TARGET)) {
        // Update our global stat struct
        st.st_size = *(size_t *)INPUT_SZ_ADDR;

        // Send it back to the caller, skip syscall
        memcpy(__stat_buf, &st, sizeof(struct stat));
        ret = 0;
    }

    // Just a normal stat, send to real xstat
    else {
        ret = real_xstat(__ver, __filename, __stat_buf);
    }

    return ret;
}

// Exploratory hooks to see if we're using fopen() related functions to open
// our input file
FILE* fopen(const char* pathname, const char* mode) {
    printf("** fopen() called for '%s'\n", pathname);
    exit(0);
}

// Our fopen hook, return a FILE* to the caller, also, if we are opening our
// target make sure we're not able to write to the file
FILE* fopen64(const char* pathname, const char* mode) {
    // Resolve symbol on demand and only once
    if (NULL == real_fopen64) {
        real_fopen64 = _resolve_symbol("fopen64");
    }

    // Check to see what file we're opening
    FILE* ret = NULL;
    if (!strcmp(FUZZ_TARGET, pathname)) {
        // We're trying to open our file, make sure it's a read-only mode
        if (strcmp(mode, "r")) {
            printf("** Attempt to open fuzz-target in illegal mode: '%s'\n", mode);
            exit(-1);
        }

        // Open shared memory FILE* and return to caller
        ret = fmemopen((void*)INPUT_ADDR, *(size_t*)INPUT_SZ_ADDR, mode);
        
        // Make sure we've never fopen()'d our fuzzing target before
        if (faked_fp) {
            printf("** Attempting to fopen64() fuzzing target more than once\n");
            exit(-1);
        }

        // Update faked_fp
        faked_fp = ret;

        // Change the filedes to something we know
        ret->_fileno = 1337;
    }

    // We're not opening our file, send to regular fopen
    else {
        ret = real_fopen64(pathname, mode);
    }

    // Return FILE stream ptr to caller
    return ret;
}

// Hook for __fxstat
int __fxstat (int __ver, int __filedesc, struct stat *__stat_buf) {
    // Resolve the real fxstat
    if (NULL == real_fxstat) {
        real_fxstat = _resolve_symbol("__fxstat");
    }

    int ret = -1;

    // Check to see if we're stat'ing our fuzz target
    if (1337 == __filedesc) {
        // Patch the global struct with current input size
        st.st_size = *(size_t*)INPUT_SZ_ADDR;

        // Copy global stat struct back to caller
        memcpy(__stat_buf, &st, sizeof(struct stat));
        ret = 0;
    }

    // Normal stat, send to real fxstat
    else {
        ret = real_fxstat(__ver, __filedesc, __stat_buf);
    }

    return ret;
}

// Hook for fcntl
int fcntl(int fildes, int cmd, ...) {
    // Resolve fcntl symbol if needed
    if (NULL == real_fcntl) {
        real_fcntl = _resolve_symbol("fcntl");
    }

    if (fildes == 1337) {
        return O_RDONLY;
    }

    else {
        printf("** fcntl() called for real file descriptor\n");
        exit(0);
    }
}

// Map memory to hold our inputs in memory and information about their size
static void _create_mem_mappings(void) {
    void *result = NULL;

    // Map the page to hold the input size
    result = mmap(
        (void *)(INPUT_SZ_ADDR),
        sizeof(size_t),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_SZ_ADDR)) {
        printf("** Err mapping INPUT_SZ_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Let's actually initialize the value at the input size location as well
    *(size_t *)INPUT_SZ_ADDR = 0;

    // Map the pages to hold the input contents
    result = mmap(
        (void *)(INPUT_ADDR),
        (size_t)(MAX_INPUT_SZ),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        0,
        0
    );
    if ((MAP_FAILED == result) || (result != (void *)INPUT_ADDR)) {
        printf("** Err mapping INPUT_ADDR, mapped @ %p\n", result);
        exit(-1);
    }

    // Init the value
    memset((void *)INPUT_ADDR, 0, (size_t)MAX_INPUT_SZ);
}

// Create a "legit" stat struct globally to pass to callers
static void _setup_stat_struct(void) {
    int result = __xstat(0x1337, FUZZ_TARGET, &st);
    if (-1 == result) {
        printf("** Err creating stat struct for '%s' during load\n", FUZZ_TARGET);
    }
}

// Used for testing, load /bin/ed into the input buffer and update its size info
#ifdef TEST
static void _test_func(void) {    
    // Open TEST_FILE for reading
    int fd = open(TEST_FILE, O_RDONLY);
    if (-1 == fd) {
        printf("** Failed to open '%s' during test\n", TEST_FILE);
        exit(-1);
    }

    // Attempt to read max input buf size
    ssize_t bytes = read(fd, (void*)INPUT_ADDR, (size_t)MAX_INPUT_SZ);
    close(fd);

    // Update the input size
    *(size_t *)INPUT_SZ_ADDR = (size_t)bytes;
}
#endif

// Routine to be called when our shared object is loaded
__attribute__((constructor)) static void _hook_load(void) {
    // Create memory mappings to hold our input and information about its size
    _create_mem_mappings();

    // Setup global "legit" stat struct
    _setup_stat_struct();

    // If we're testing, load /bin/ed up into our input buffer and update size
#ifdef TEST
    _test_func();
#endif
}
```
