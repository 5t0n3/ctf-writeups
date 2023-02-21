import random, time

if(time.time() > 1676086400):
    exit(1)

b = open("flag.png", "rb").read()
random.seed(round(time.time()))

B = []
for _ in range(len(b)):
    B.append(random.randint(0,255))

f = bytearray(b)
for i in range(len(b)):
    f[i] = b[i] ^ B[i]

# Override flag. muawahahahah
w = open("flag.png", "wb")
w.write(f)