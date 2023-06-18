# Shard

**Author**: Neobeo

**Category**: Crypto

Flag: `SEE{Cryptic_clue:_Bit_of_RSA_mixed_with_DH}`

## Description

I overheard Alice sharing a flag with Bob, but it was encrypted.

## Difficulty

Hard

## Deployment

NIL

## Solution

1. First we use `hint` to identify all possible values of `isqrt(p)`; there are only 7 possible values if we assume wlog that `p < q`.
2. Use Coppersmith to extend it to a full value of `p`. Since we're at the limit of the Coppersmith, we will need to brute-force a few bits.
3. Once p and q are recovered, we need to solve the DLOG problem. We use n-adic numbers to solve it mod $2^{2048} \approx 3^{1292}$.
4. This is not sufficient to reach $3^{1337} \approx 2^{2119}$, but fortunately both `p-1` and `q-1` have small enough factors to get us just over the limit.
