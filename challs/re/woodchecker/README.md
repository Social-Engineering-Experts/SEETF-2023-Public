# Woodchecker

**Author**: Neobeo

**Category**: RE

Flag: `SEE{pIcKyP1CIF0rmeS}`

## Description

Entering the realm of the Woodpecker's Nest, you discover that the [Woodpecker](https://github.com/radical-semiconductor/woodpecker) is nothing more than a low-level drone that only knows four instructions.

Decode the enigmatic instructions and unveil the secrets that soar beyond the skies.

## Difficulty

Medium

## Deployment

NIL

## Solution

There's a few intended paths to solve this. You can either:
1. Simplify the repeated bits into single instructions (e.g. INC(160)) and discover that there's a lot of repetition. From there, you can generate the entire program in maybe 40 lines of python code, which allows you to notice that the transformation is linear. Specifically, it just repeats xors each bit[i] into bit[i-1] and bit[i-2]. Or,
2. Start with the trail of "LOAD-CDEC"s at the end to infer that you must end up with a trail of 1s. Equivalently, not succeeding means you end at a higher address, so guess various strings and keep track of where the final address it. In this way you can solve one character at a time, right-to-left. This is the implementation provided by the solve script.