import random

t = 1676086400 # from time check
while t > 0:
    random.seed(t)
    res1 = random.randint(0, 255)
    res2 = random.randint(0, 255)
    res3 = random.randint(0, 255)

    # 250/42/215 were obtained by xoring the first 3 bytes of the PNG magic/flag.png
    if res1 == 250 and res2 == 42 and res3 == 215:
        break

    t -= 1
print(f"{t = }")
