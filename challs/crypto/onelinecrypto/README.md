# onelinecrypto

**Author**: Neobeo

**Category**: Crypto

Flag: `SEE{luQ5xmNUKgEEDO_c5LoJCum}`

## Description

How to bypass this line?

```
assert __import__('re').fullmatch(r'SEE{\w{23}}',flag:=input()) and not int.from_bytes(flag.encode(),'big')%13**37
```

## Difficulty

Medium/Hard (Insanity Check)

## Deployment

NIL

## Solution

LLL + branch-and-bound. Longer writeup TBA.