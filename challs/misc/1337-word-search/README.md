# 1337 Word Search

**Author**: Neobeo

**Category**: Misc

Flag: `SEE{you_found_me_now_try_the_1337er_one}`

## Description

It's a big [word search](https://en.wikipedia.org/wiki/Word_search). Find the flag hidden in the grid, in any of the eight directions (horizontal, vertical, or diagonal).

## Difficulty

Beginner Friendly

## Deployment

NIL

## Solution

Do a brute force search over all 1337x1337 starting positions, over all 8 directions, until we find the first four characters matching `SEE{`.