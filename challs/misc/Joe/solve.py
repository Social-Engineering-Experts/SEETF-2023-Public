from pwn import *

r = remote('win.the.seetf.sg', 4001)
r.recvuntil(b"Joe in a ").decode("utf-8")
a = r.recvuntil(b"D plane.").decode("utf-8")
n = int(a.replace("D plane.", ""))
r.recvuntil(b"> ")
print(f'Dimentions: {n=}')

def check(points, end=False):
    sending = ' '.join([str(p) for p in points])
    #print(sending)
    r.sendline(bytes(sending, 'utf-8'))
    recving = r.recv()
    result = None
    if "Outside" in str(recving):
        result = 0
    elif "Inside" in str(recving):
        result = 1
    elif "Joe" in str(recving):
        result = 2
    #print(recving)
    if not b'Find Joe' in recving and end:
        print(recving.decode("utf-8").split("\n")[1])
        exit(1)
    return result

i = 0
while 1:
    curr = [0 for _ in range(n)]
    attempts = 0
    for k in range(n):
        nx0 = -10000000000
        nx1 = 0
        px0 =  10000000000
        px1 = 0
        x = 0
        nx = 0
        px = 0
        while 1:
            x = nx0+((nx1-nx0)//2)
            if x == nx0 or x == nx1:
                nx = x
                break
            new = curr.copy()
            new[k] = x
            res = check(new)
            attempts += 1
            if res == 1:
                nx1 = x
            elif res == 0:
                nx0 = x

        x = 0
        while 1:
            x = px1+((px0-px1)//2)
            if x == px1 or x == px0:
                px = x
                break
            new = curr.copy()
            new[k] = x
            res = check(new)
            attempts += 1
            if res == 1:
                px1 = x
            elif res == 0:
                px0 = x

        midx = nx + ((px-nx)//2)
        curr[k] = midx

    #print(curr)
    if check(curr, True) == 2:
        attempts += 1
        print(f"Calculated center of circle {i} in {attempts} attempts")
    i += 1