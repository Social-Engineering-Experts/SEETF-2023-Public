from Crypto.Util.strxor import strxor

c0 = bytes.fromhex('b99665ef4329b168cc1d672dd51081b719e640286e1b0fb124403cb59ddb3cc74bda4fd85dfc')
c1 = bytes.fromhex('a5c237b6102db668ce467579c702d5af4bec7e7d4c0831e3707438a6a3c818d019d555fc')
m1 = b'a'*36

xorKeyStream = strxor(m1, c1)
m0 = strxor(xorKeyStream, c0[:len(xorKeyStream)]) + b'ES'
print(m0[::-1])
#b'SEE{n3vEr_reU53_rC4_k3y5ss5s:cafe2835}'