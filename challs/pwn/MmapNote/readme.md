# Shellcode As A Service

**Author**: hibana(discord: 0x62#2325)

**Category**: Pwn

Flag: `SEE{m4st3r_0f_mm4p_5ee2a719bc6a8209e7295d4095ff5181}`

## Description

I made a basic note program but with sandbox. And no more chunk for house of xxx. Can you still get the flag?

## Difficulty

Medium

## Solution

There is a bof in line 139 of `chall.c`:
```c
char buf[16];
    while (check)
    {
        menu();
        read(0, buf, 160);
```

but we have to get the canary first. In `writeNote()` if we make `size[idx]` more than 0x1000, it will return but still store it in the array. So in `readNote()` we can read more than 0x1000 bytes. We will create new note until mmap return a region that right before the region of canary. Then we can leak the canary and build ROP chain. Before `main()` return, it call `filter()` to kill bad system call. We can only use `open`, `write`, `mmap`. So we have to use `mmap` to read flag and `write` to print it.

Solve script [here](solve/solve.py).

**NOTE**: The solve script is test on local. I hard code the number of note to create. If you run it on remote, you have to change the number of note to create. Just create new note until the region of canary is right after the region of mmap.