# Sol script if x (the secret/flag) is known

import random
import re
from pwn import remote

from Crypto.Util.number import bytes_to_long

FLAG = "SEE{1_571ll_h4v3_n0_kn0wl3d63}"

x = bytes_to_long(FLAG.encode())
conn = remote("localhost", 1337)
p = int(conn.recvuntil(b"\n", drop=True)[4:].decode())
g = int(conn.recvuntil(b"\n", drop=True)[4:].decode())
y = int(conn.recvuntil(b"\n", drop=True)[4:].decode())

for _ in range(30):
    r = random.randint(0, p - 2)
    C = pow(g, r, p)
    w = (x + r) % (p - 1)
    req = conn.recvuntil(b": ").decode()[-3]
    if req == "w":
        conn.sendline(str(w).encode())
    elif req == "r":
        conn.sendline(str(r).encode())
    conn.recv()
    conn.sendline(str(C).encode())

final = conn.recv()

print(re.search(r"SEE\{.+}", final.decode())[0])
