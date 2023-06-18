# Linear Programming

**Author**: JuliaPoo

**Category**: RE

Flag: `SEE{sT1lL_Us!nG_pR3&ENt?}`

## Description

We've intercepted a message from the future! Unfortunately the message is protected by a password, and the software checks the password by running a GINORMOUS linear program. I guess the future just has more powerful computers, but we'd have to settle for waiting a few seconds for the result. Our team has extracted out the password checking code into a nice python script, can you recover the password?

Note: Access to a fast MILP solver isn't needed to solve this challenge.

## Difficulty

Hard

## Deployment

NA

## Solution

This is possibly the most difficult challenge I've written, and I can't make it easier because of how stupidly fast modern MILP solvers are.

Read `solve/solve.ipynb`

TLDR:

1. Figure out how to relate each variable to the input. Should result in a graph (like an AST) of operations
2. Reverse each operation. There are only two. One of them is `XOR` the other one is whatever, just treat it like an SBOX.
3. Figure out which variables are the "terminal", i.e., no matter the input, these variables _must_ have a certain value
4. Attempt to symbolise the first few layers of the AST.
    - Via backslicing, realise that the subgraph dependent on `input[:80]` is completely seuperate from `input[80:]`. Not only that, the two subgraphs are very similar
5. Upon symbolising, reverse to realise that `input[:64]` can easily be computed from the "terminal" variables, if we know `input[64:80]`
6. Generate an efficient bruteforce script for `input[64:80]` to recover `input[:80]`. I.e., the first half of the flag
7. Do the same for `input[80:]`, i.e., the 2nd half of the flag.