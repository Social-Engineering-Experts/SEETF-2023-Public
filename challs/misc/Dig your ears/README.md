# Dig your ears

**Author**: Infintesky

**Category**: Misc

Flag: `SEE{M4yB3_1t5_t1me_T0_g3t_y0ur_e4rs_che3cked._.}`

## Description

```
Instead of SEEing the flag, maybe you can hear the flag. 

Bits are encoded between 1200Hz and 2400Hz ranges every 10 milliseconds, use your eyes to SEE any pattern. Maybe then you can hear the flag. 
```

## Deployment

Just the file in dist

## Difficulty

Hard

## Solution
Hash of wave file: 984f78ffff6f65ddab6e93d7cac5694b1ce33ed65a6ed8c0918d2b2fbfcf00be

Identify that there is a recurring pattern every 10 millisecond. Slice the wave file into 10 milliseconds chunks. On each chunk, perform Fast Fourier Transform to extract the dominant frequency. If the frequency is 1200Hz, it is a 0 bit, if it is 2400Hz, it is 1 bit. These bits combines to form the flag data. Convert flag data from binary to ascii to get the flag.
