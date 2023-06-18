# Sol script if x (the secret/flag) is unknown

import random
import re
from pwn import remote

conn = remote("win.the.seetf.sg", 3002)
p = int(conn.recvuntil(b"\n", drop=True)[4:].decode())
g = int(conn.recvuntil(b"\n", drop=True)[4:].decode())
y = int(conn.recvuntil(b"\n", drop=True)[4:].decode())

for _ in range(30):
    req = conn.recvuntil(b": ").decode()[-3]
    if req == "w":
        w = random.randint(0, p - 2)
        C = pow(g, w, p) * pow(y, -1, p) % p
        conn.sendline(str(w).encode())
    elif req == "r":
        r = random.randint(0, p - 2)
        C = pow(g, r, p)
        conn.sendline(str(r).encode())
    conn.recv()
    conn.sendline(str(C).encode())

final = conn.recv()

print(re.search(r"SEE\{.+}", final.decode())[0])
