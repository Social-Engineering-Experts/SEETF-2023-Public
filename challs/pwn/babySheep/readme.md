# babySheep

**Author**: flyyee

**Category**: Pwn

Flag: `SEE{U53_L1bc_4Ft3r_fr33_02d21ec287070250a486feab8d10e60b}`

## Description

Sorry, no sheep here.

## Difficulty

Medium

## Solution

TLDR: Overlapping stack -> UAF -> atexit hijack -> pointer guard bypass

First, notice that the operations, Output, Update, Delete have an identical stack frame, in the same location in memory:
```c
int idx;    // Stack[-0x20]
int buffer_size;   // Stack[-0x1c]
struct text *ptr;  // Stack[-0x18]
```
After deleting a text, when we enter the `output()` and `update()` functions, `ptr` and `size` remain uninitialized if we pass in an invalid value for `idx`. This gives us our UAF read and write respectively. However, our UAF write is limited as we can only write +0x10 from the start of the chunk and -0x8 from the end of the chunk in update(). This means that the typical approach to exploiting a UAF is not possible. However, we can still get a libc leak via unsorted bin, as per usual.

Next, let's look at `atexit()`. Reading through the libc source, we see that `atexit()` stores the exit handlers is an array in a `exit_function_list` [struct](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/exit.h#L55), which contains an array `exit_function fns[32]` of 32 exit functions. When `atexit()` has registered more than this number of exit functions, it creates a new `exit_function_list` struct with [calloc](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/cxa_atexit.c#L106) (the structs form a linked list). We can trigger this behaviour by repeatedly calling `delete()`, which registers a new exit handler function every time we successfully delete a text, filling up the `exit_function fns[32]` array.

With our UAF, we can hijack the `exit_function_list` struct, allowing us to run an arbitrary function before the program exits. The function pointers in the `exit_function fns[32]` are _mangled_. Pointer mangling "is a glibc security feature which aims to increase the difficulty to attackers of manipulating pointers - particularly function pointers - in glibc structures". Here is the algorithm:
```c
# ifdef __ASSEMBLER__
#  define PTR_MANGLE(reg)	xor %fs:POINTER_GUARD, reg;	\
                            rol $2*LP_SIZE+1, reg
```
The function pointer is xor-ed with the pointer guard, a 64-bit random value stored in the thread control block (the canary is located there too). The result is rolled left by 0x11 (2\*8+1). The typical way to hijack `exit_function fns` is to leak a mangled pointer to a known address, e.g. `_dl_fini()` or `NULL`. However, the only mangled pointer leak we have is of the `cleanup()` function registered by `delete()`. We don't know its address because the binary is compiled under PIE. Instead, we can make use of the proximity of the `cleanup()` and the `backdoor()` function in the binary's memory. The function address differ only by the least significant byte. The final step involves some arithmetic to make use of this fact. Empirically, we can notice that only the third byte of the mangled function pointers for `cleanup()` and `backdoor()` differ, and use this to obtain the mangled `backdoor()` function pointer.

Full exploit script: [exp.py](solve/exp.py)