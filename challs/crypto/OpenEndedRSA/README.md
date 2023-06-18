# OpenEndedRSA

**Author**: Warri

**Category**: Crypto

Flag: `SEE{0dd_3vEN:deadbeef}`

## Description

```
I was told my RSA implementation is extremely insecure and vulnerable...
I'll make this open ended for yall to take a look...find the vulnerability and I'll give you the flag!
```

## Deployment

nil

## Difficulty

Begineer-Friendly

## Solution

1. s is odd. p and pp are primes, and `p**2 + pp**2 == s`
2. p is a 512 bit prime, so p must be odd
3. odd = odd + even as odd + odd = even, so pp**2 must be even
4. This means pp must be even. By (1), pp must therefore be 2
5. We can then find p, and from there RSA decryption is trivial
