from cpu import CPU

lines = list(open('woodchecker.wpk').readlines())

cs = ''.join(map(chr, range(32, 127)))

known = ''
while len(known) < 20:
    arr = []
    for c in cs:
        flag = c * (20 - len(known)) + known
        cpu = CPU()
        cpu.mem[:len(flag)] = flag.encode()
        
        for instr in lines:
            cpu.execute(instr)
            
        arr.append((cpu.addr, c))
          
    arr = sorted(arr)
    print(arr[:5])
    
    known = arr[0][1] + known
    print(f'{known = }')