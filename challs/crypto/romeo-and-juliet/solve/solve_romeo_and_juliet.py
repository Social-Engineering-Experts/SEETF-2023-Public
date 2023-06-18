from sage.all import *
from pwn import *
from Crypto.Util.number import long_to_bytes

#with process(['python', 'romeo_and_juliet.py']) as sh:
with remote('192.168.0.232', 1337) as sh:
    sh.readuntil(b'noise: ')
    flag1 = int(sh.readline())

    def get(n):
        sh.sendline(str(n).encode())
        sh.readuntil(b'hears: ')
        return int(sh.readline())

    a = get(-1)
    m = get(a) + 1
    assert get(m) == 0, "Fails about 50% of the time, try again"
    n = get(get(-a)) + a
    assert get(n) == 0, "Fails about 4% of the time (if the above succeeds), try again"
    flag2 = get(-get(flag1))
   
def GCD(a, b):
    
    def HGCD(a, b):
        if 2 * b.degree() <= a.degree() or a.degree() == 1:
            return 1, 0, 0, 1
        m = a.degree() // 2
        a_top, a_bot = a.quo_rem(x**m)
        b_top, b_bot = b.quo_rem(x**m)
        R00, R01, R10, R11 = HGCD(a_top, b_top)
        c = R00 * a + R01 * b
        d = R10 * a + R11 * b
        q, e = c.quo_rem(d)
        d_top, d_bot = d.quo_rem(x**(m // 2))
        e_top, e_bot = e.quo_rem(x**(m // 2))
        S00, S01, S10, S11 = HGCD(d_top, e_top)
        RET00 = S01 * R00 + (S00 - q * S01) * R10
        RET01 = S01 * R01 + (S00 - q * S01) * R11
        RET10 = S11 * R00 + (S10 - q * S11) * R10
        RET11 = S11 * R01 + (S10 - q * S11) * R11
        return RET00, RET01, RET10, RET11

    q, r = a.quo_rem(b)
    if r == 0:
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == 0:
        return c.monic()
    q, r = c.quo_rem(d)
    if r == 0:
        return d
    return GCD(d, r)
    
print('Calculating...')

x = Zmod(m)['x'].gen()
f, g = x**65537-flag1, (n-x)**65537-flag2
print(long_to_bytes(int(x-GCD(f,g).monic())))