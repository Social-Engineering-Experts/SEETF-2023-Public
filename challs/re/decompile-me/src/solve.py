from pwn import xor

with open('output.txt', 'rb') as f:
    output = f.read()

a = output[0:len(output)//3]
b = output[len(output)//3:2*len(output)//3]
c = output[2*len(output)//3:]

print((xor(b,a,c,14,9)+xor(c,14)+xor(a,c,14)).decode('utf-8'))