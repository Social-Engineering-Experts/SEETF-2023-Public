from sage.all import *
from sage.modular.ssmod.ssmod import Phi2_quad, Phi_polys

p = 2**8 * 3**15 - 1
F = GF(p**2, name='i', modulus=[1,0,1])
pi = '31415926535897932384626433832795'

tmp = {int(pi[a:b]) for b in range(len(pi)) for a in range(b)}
js = [x for x in tmp if x < p and EllipticCurve(j = F(x)).is_supersingular()]
assert js == [314159] # only possible endpoint

x = F['x'].gen()

def traverse(depth, curr, prev=None):
    if depth == 0: return
    poly = Phi_polys(2, x, curr) if prev is None else Phi2_quad(x, prev, curr)
    for a,_ in poly.roots():
        yield a, curr
        yield from traverse(depth-1, a, curr)
        
dic1={a:b for a,b in traverse(15, F(0))}
dic2={a:b for a,b in traverse(14, F(314159))}

mitm = list(dic1.keys() & dic2.keys())
assert mitm

def backtrace(n, dic):
    yield n
    while n in dic:
        n = dic[n]
        yield n
    
path = list(backtrace(mitm[0], dic1))[::-1] + list(backtrace(mitm[0], dic2))[1:]
print(path)

# we are essentially done. the rest is just to pipe it through the remote and get a flag
from pwn import *
payload='\n'.join(str(sorted(a for a,_ in Phi_polys(2, x, a).roots()).index(b)+1) for a,b in zip(path, path[1:]))

#with process(['sage', 'isogeny_maze.sage']) as sh:
with remote('win.the.seetf.sg', 3000) as sh:
    sh.sendline(payload.encode())
    print(sh.readline_contains(b'SEE{'))
