# Hard To Write

**Author**: JuliaPoo

**Category**: Crypto

Flag: `SEE{Sl1dinG_D1ffeR3nt14L_BAb5y:1kcKj}`

## Description

```
This challenge was so hard to write.

Differential Cryptanalysis Pg 19-29: 
https://ioactive.com/wp-content/uploads/2015/07/ldc_tutorial.pdf
```

## Deployment

At the `src` directory, run
```
docker build -t chal-hard-to-write .
docker run -d -p "0.0.0.0:<port>:1337" -h "chal-hard-to-write" --name="chal-hard-to-write" chal-hard-to-write
```

## Difficulty

Hard

## Solution

1. Notice that the cipher is essentially an SPN
1. Plot to DDT of the SBOX to see that it's fucked
2. Notice that there's essentially 12 rounds of SBOX
3. Find a set of differentials trails that cut through 12 rounds
4. Exploit the differentials to recover most of the last round key
5. Bruteforce the rest of the key