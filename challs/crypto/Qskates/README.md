# Qskates

**Author**: Warri

**Category**: Crypto

Flag: `SEE{qUanTuM_k3Y_d1sTribUt1ON_r_0nlY_t0_b3_u5ed_0nce:12843}`

## Description

```
Alice and Bob love skating so much, they've gotten Eve into it!

Turns out Eve is a skater herself and wants to know Alice's secret. She's placed herself right in the middle of their conversation, can you help her figure out the secret?
```

## Deployment

At the `src` directory, run
```
docker build -t Qskates .
docker run -p OUTER_PORT:INNER_PORT -d -t Qskates
```

## Difficulty

Medium

## Solution

1. This is basically Quantum Key Distribution using the BB84 Protocol
2. Perform an Intercept and Resend attack (https://en.wikipedia.org/wiki/Quantum_key_distribution#Attacks_and_security_proofs) to side channel and derive Bob's bases
3. From Bob's bases, deriving the key is trivial
4. Decrypt the AES with the key and provided iv to obtain the flag
