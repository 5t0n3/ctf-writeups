n = 996905207436360486995498787817606430974884117659908727125853
e = 65537
c = 375444934674551374382922129125976726571564022585495344128269

# p, q = n.prime_factors()
p, q = [861346721469213227608792923571, 1157379696919172022755244871343]

MP = Zmod(p)
MQ = Zmod(q)

m = c
for _ in range(16):
    mp = ZZ(MP(m).nth_root(2))
    mq = ZZ(MQ(m).nth_root(2))
    m = crt([mp, mq], [p, q])

print(int(m).to_bytes(m.bit_length()//8+1, byteorder="big").decode())
