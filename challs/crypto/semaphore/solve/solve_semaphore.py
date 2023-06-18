from sage.all import *
from Crypto.Util.number import bytes_to_long

# https://neuromancer.sk/std/x962/prime192v1
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
K = GF(p)
a = K(0xfffffffffffffffffffffffffffffffefffffffffffffffc)
b = K(0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1)
E = EllipticCurve(K, (a, b))
G = E(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)
E.set_order(0xffffffffffffffffffffffff99def836146bc9b1b4d22831 * 0x1)
n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

zz = open('semaphore.py').readlines()[12:-1]
print(len(zz)) # 106

def get_rs(z):
    bs = bytes.fromhex(z)
    return bytes_to_long(bs[:24]), bytes_to_long(bs[24:])
    
r0, s0 = get_rs(zz[0])
r1, s1 = get_rs(zz[3])
r2, s2 = get_rs(zz[5])
diff = 256**23 * G

def possible_Qs():
    P1, P2 = E.lift_x(Integer(r1)), E.lift_x(Integer(r2))
    for m1 in [1, -1]:
        for m2 in [1,-1]:
            Q = (m1 * s1 * P1 - m2 * s2 * P2) * pow(r1-r2,-1,n)
            H = m1 * s1 * P1 - r1 * Q
            print(f'{H = }')

            test = (H + r0 * Q) * pow(s0, -1, n)
            if test[0] == r0:
                yield Q
            
qs = list(possible_Qs())
print(qs)

Q = qs[0]
dic = {}
newnum = 0
lst = []
for zzz in zz:
    r, s = get_rs(zzz)
    P = E.lift_x(Integer(r))
    H1 = s * P - r * Q
    H2 = -s * P - r * Q
    #print(f'{H1[0],H2[0]}')
    lst.append(H1)
    
    if H1 in dic:
        val = dic[H1]
        dic[H2] = val
    elif H2 in dic:
        val = dic[H2]
        dic[H1] = val
    else:
        val = newnum
        newnum += 1
        dic[H1] = val
        dic[H2] = val

# we know the flag begins with 'SEE{' and ends with '}', which immediately gives us 6 nibbles.
# we can then slowly work out the rest of the permutation in a similar cryptogram manner, or a 10! brute force
perm = '5347b619f0cdea28'
print(bytes.fromhex(''.join(perm[dic[H]] for H in lst)))