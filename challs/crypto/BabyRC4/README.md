# OpenEndedRSA

**Author**: Warri

**Category**: Crypto

Flag: `SEE{n3vEr_reU53_rC4_k3y5ss5s:cafe2835}`

## Description

```
I have a simple RC4 encryption oracle. Shouldn't be that hard to break...right?
```

## Deployment

nil

## Difficulty

Begineer-Friendly

## Solution

1. RC4 merely generates a stream of numbers to xor with a given plaintext
2. Since the key used in the RC4 (in Crypto.Cipher its referred to as ARC4) is constant in both enc() oracles, one can xor c1 and b'a'*36 to get the keystream used for the first 36 chars.
3. One then xors the keystream with c0, append the starting two letters to then obtain the flag.
