# 1337er Word Search

**Author**: Neobeo

**Category**: Misc

Flag: `SEE{t4StELe5s_4tTR1buT3}`

## Description

It's a bigger [word search](https://en.wikipedia.org/wiki/Word_search). Find the flag hidden in the grid, in any of the eight directions (horizontal, vertical, or diagonal).

## Difficulty

Medium/Hard

## Deployment

NIL

## Solution

TBA -- you do some maths to determine that `SEE{` only appears once in some specific position, but I need to double-check this.

For now you can enter this in the console to see the flag:
```js
s = '';
for (let i = 0n; !s.endsWith('}'); i++)
	s += get(257n - i, 2n**1337n - 233n + i);
```