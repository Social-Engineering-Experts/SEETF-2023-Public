key = b"hithisisakey"
ct = bytes.fromhex("fde5f5e12640b9860f526a9601861e752e84d866825c415549f454fe8ba3")
magic = [0x6e, 0x94, 0x68, 0xfb, 0x37, 0xb8, 0x9a, 0x85, 0x69, 0x9e, 0x99, 0x6b, 0x90, 0xa6, 0xce, 0x78, 0xa1, 0x1a, 0x27, 0x4f, 0x33, 0x8f, 0x2a, 0xed, 0x97, 0xe5, 0x7b, 0xb6, 0xd0, 0xdd, 0x24, 0x39]


def rc4(ct, _k):
    # ksa
    S = [i for i in range(256)]
    j = 0
    for i in range(len(S)):
        j = (j + S[i] + _k[i % len(_k)]) % 256
        S[i], S[j] = S[j], S[i]

    # prga
    keys = [None] * len(ct)
    j = k = 0
    for c in range(len(ct)):
        j = (j + 1) % 256
        i = S[j]
        k = (i + k) % 256
        S[j] = S[k]
        S[k] = i
        keys[c] = S[(i + S[j]) % 256]

    # xor
    pt = b""
    for i in range(len(ct)):
        pt += ((ct[i] - magic[i] + keys[i]) % 256).to_bytes(1, "big")
    return pt


print(rc4(ct, key))
