# Non-neutrality

**Author**: Neobeo

**Category**: Crypto

Flag: `SEE{__literally_any_bias_is_bad__}`

## Description

My neutral OTPs got destroyed last year; all that's left are the non-neutral ones.

## Difficulty

Hard

## Deployment

NIL

## Solution

This challenge require fairly tight use of probability and statistics. For example, we can immediately learn that the flag must have an even number of set bits just by looking at the parity of all 65536 messages (31114 of them have an even number of set bits, the remaining 34422 have an odd number of set bits).

We can make some assumptions about the flag, i.e. that it begins with `SEE{`, ends with `}`, and the inner characters are all ASCII. This gives us a strong enough seed to proceed to guess the remaining bits in a probabilistic way. We do this iteratively: find the bits that we think are most likely to be predicted correctly by our model, then iteratively use these to predict other bits. We might end up with a small number of errors at the end, but hopefully the intended flag pops out sufficiently clearly.