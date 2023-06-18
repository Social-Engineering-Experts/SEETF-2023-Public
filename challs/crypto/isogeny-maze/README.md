# Isogeny Maze

**Author**: Neobeo

**Category**: Crypto

Flag: `SEE{SIKE!_made_you_implement_a_MITM_attack}`

## Description

We had a maze last year called To Infinity. Here's the sequel.

## Difficulty

Hard

## Deployment

`docker-compose up -d`

## Solution

This is the isogeny graph, mainly made popular by SIKE.

First, we look for substrings of pi that are supersingular, and it turns out that 314159 is the only one. Then we can run a meet-in-the-middle attack from 0 to 314159. We estimate that this is around $\log_2(p) \approx 32$ steps.
