from pwn import xor

with open('flag.txt', 'rb') as f:
    flag = f.read()

a = flag[0:len(flag)//3]
b = flag[len(flag)//3:2*len(flag)//3]
c = flag[2*len(flag)//3:]

a = xor(a, int(str(len(flag))[0])+int(str(len(flag))[1]))
b = xor(a,b)
c = xor(b,c)
a = xor(c,a)
b = xor(a,b)
c = xor(b,c)
c = xor(c, int(str(len(flag))[0])*int(str(len(flag))[1]))

enc = a+b+c

with open('output.txt', 'wb') as f:
    f.write(enc)