from collections import Counter
from pwn import bits, unbits
from math import inf, log, comb
from functools import cache

def cmb(x,y): return 0 if y < 0 else comb(x, y)
def uc(a,b): return 2**(a+b-1) - cmb(a+b,a)
def ln(x): return log(x) if x else -inf

@cache
def lu(a,b):
    return ln(uc(a,b))

def getbit(x, i):
    return (x >> (LEN - 1 - i)) & 1


arr = [int(x) for x in open('nn_out.txt').readlines()]
print(Counter(bin(x).count('1')%2 for x in arr))
# Counter({1: 34422, 0: 31114})
# means the flag has an even number of set bits

arr = [x for x in arr if bin(x).count('1')%2 == 0]
LEN = max(arr).bit_length()
assert LEN == 272

template = [None] * LEN
template[::8] = [0] * (LEN//8)
template[:32] = bits(b'SEE{')
template[-8:] = bits(b'}')

while True:
    tmp = [0] * LEN
    nones = [i for i in range(LEN) if template[i] is None]
    if len(nones) == 0: break
    for x in (arr):
        c1 = sum([getbit(x,i)^v for i,v in enumerate(template) if v is not None])
        c0 = LEN - len(nones) - c1
        a = LEN//2 - c0
        b = LEN//2 - c1
        d = lu(a-1,b) - lu(a,b-1)
        for i in nones:
            if getbit(x, i): tmp[i] += d
            else: tmp[i] -= d
    win = sorted((-abs(tmp[i]),i,~~(tmp[i]>0)) for i in nones)[:10]
    for _,i,v in win:
        template[i] = v
    print(win[-1], unbits([~~(tmp[i]>0) if x is None else x for i,x in enumerate(template)]))
    
# in this case we end with b'SEE{__litevally_any_bias_is_bad__}' which as one bit of error
# the intended flag is SEE{__literally_any_bias_is_bad__}