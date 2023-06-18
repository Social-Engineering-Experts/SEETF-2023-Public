# Dumb challenge

**Author**: TheMythologist

**Category**: Crypto

Flag: `SEE{1_571ll_h4v3_n0_kn0wl3d63}`

## Description

This sus pigeon wants to prove that an object is ultraviolet in colour, but I'm ultraviolet-blind!

## Deployment

At the `src` directory, run

```
docker build -t chal-dumb-chall .
docker run -d -p "<port>:1337" --name="chal-dumb-chall" chal-dumb-chall
```

## Difficulty

Medium

## Solution

The seed is meant to be an introductory challenge to zero-knowledge proofs, and the potentiall pitfalls around it.

1. Since you know whether the service is requesting for W or r, you can calculate the answer pre-emptively (even though you will never know both W and r).
