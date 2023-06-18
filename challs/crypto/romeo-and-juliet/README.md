# Romeo and Juliet

**Author**: Neobeo

**Category**: Crypto

Flag: `SEE{O_Franklin-Reiter,_Franklin_Reiter,_wherefore_art_thou_Franklin-Reiter?_d0df1731bfea05134a97fbb244a85547}`

## Description

Romeo and Juliet have opened a secure channel where they can feel free to say anything they want to each other.

## Difficulty

Medium

## Deployment

`docker-compose up -d`

## Solution

We can learn the two moduli by noticing that `-1` gets wrapped to `n-1` and so on. In particular, assume m and n are the moduli with m > n. Then if x is the flag, we can learn x^65537 and (n-x)^65537 mod m. We can then take the gcd. This can take about an hour to compute, but we can reduce this to mere seconds by using the half-gcd.