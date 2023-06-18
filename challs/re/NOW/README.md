# NOW

**Author**: Warri

**Category**: Re

Flag: `SEETF{bTw_NOW_1s_riv3st_sH4m1r_Adl3m4n_cAEs4r_sh1Fted_tw3ntY_tWO}`

## Description

```
Aaaa why does this binary take so long?! I want the flag NOW, N. O. W. NOW!!!!!
```

## Deployment

```
Give participants the ELF binary in dist folder/
```

## Difficulty

Easy/Medium

## Solution

1. One can find 3 long hexstrings by running strings on the ELF.
2. After some reversing one should find 2 functions being called in main.
3. The first is flip(), which on a hexstring d, flips every '1' in d's binary to a '0' and every '0' to a '1'
4. The second is power(), which used on two hexstrings c and d, computes pow(c,d,n) with n as the third hexstring in the binary, which stores the output in c
5. The flag is the result of c after power() is called.