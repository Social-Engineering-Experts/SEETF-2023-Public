# Semaphore

**Author**: Neobeo

**Category**: Crypto

Flag: `SEE{easy_peasy_lemon_squeezy_signature_distinguisher}`

## Description

I'm signing with my flag so you know it's the real deal.

## Difficulty

Medium

## Deployment

NIL

## Solution

First we need to obtain the public key. We cannot do this from a single signature since the hash is also unknown, but if we have two signatures with the same hash, then we can solve the linear equation with two unknowns (the unknowns here being the hash and the public key). We know the flag hex begins with `534545`, so we have some same hashes there already.

Once we have the public key, we can separate the signatures into groups of 16 different hashes, each corresponding to a different base-16 digit. We know it begins with `5345457B` and ends with `7D`, so that fixes 6 out of 16 values already. The rest we can play around like a cryptogram, or really, we can just brute force all `10!=3628800` permutations until we find one that works.