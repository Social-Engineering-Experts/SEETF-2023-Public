from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from pwn import *
from time import time
import hashlib

n = 100
start = time()
p = remote('win.the.seetf.sg', 3004)
payload = ""
l = log.progress('Working on it...')
iv = bytes.fromhex(p.recvline().rstrip()[5:].decode())
enc = bytes.fromhex(p.recvline().rstrip()[6:].decode())

known = [False] * n
for i in range(n):
	l.status(f'Progress: {i+1}/{n}')
	is_one = False
	is_random = False
	for j in range(15):
		in0 = payload + "0"
		in1 = payload + "1"
		p.sendlineafter(b'intercept: ', in0.encode())
		p.recvuntil(b'message: ')
		eve = [str(_) for _ in eval(p.recvline().rstrip().decode())]
		p.sendlineafter(b'Bob: ', ''.join(eve).encode())
		result = eval(p.recvline().rstrip().decode())
		if not result:
			is_one = True
			break
		p.sendlineafter(b'intercept: ', in1.encode())
		p.recvuntil(b'message: ')
		eve = [str(_) for _ in eval(p.recvline().rstrip().decode())]
		p.sendlineafter(b'Bob: ', ''.join(eve).encode())
		result = eval(p.recvline().rstrip().decode())
		if not result:
			break

		if j == 14:
			is_random = True

	if is_random:
		payload += "1"
	elif is_one:
		payload += "1"
		known[i] = True;
	else:
		payload += "0"
		known[i] = True;

p.sendlineafter(b'intercept: ', payload.encode())
p.recvuntil(b'message: ')
eve = [str(_) for _ in eval(p.recvline().rstrip().decode())]
p.close()

key = ""
for i, j in zip(known, eve):
	if not i:
		continue
	key += j 
print(key)
key = hashlib.sha256(key.encode()).digest()[:16]
cipher = AES.new(key=key, iv=iv, mode=AES.MODE_CBC)
flag = cipher.decrypt(enc)
print(flag)
print(f'Time taken: {time() - start}')
