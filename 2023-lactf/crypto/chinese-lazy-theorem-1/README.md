# crypto/chinese-lazy-theorem-1 (343 solves/238 points)

> I heard about this cool theorem called the Chinese Remainder Theorem, but, uh... I'm feeling kinda tired right now.

Provided: [`chinese-lazy-theorem-1.py`](chinese-lazy-theorem-1.py)

## Solution

The [Chinese remainder theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) is a real thing that can be useful in some crypto challenges, but it turns out you don't actually need it for this one :)

Based on the provided program, we know that we're trying to guess a random target number between 1 and another number n:

```python
p = getPrime(512)
q = getPrime(512)
n = p*q

target = randint(1, n)

used_oracle = False

print(p)
print(q)
```

We're also conveniently given n's two prime factors, so we can trivially compute n.

Later on in the program is the code responsible for handling our single oracle query:

```python
    # snip
    if response == "1":
        if used_oracle:
            print("too lazy")
            print()
        else:
            modulus = input("Type your modulus here: ")
            modulus = int(modulus)
            if modulus <= 0:
                print("something positive pls")
                print()
            else:
                used_oracle = True
                print(target%modulus)
                print()
```

So we get to send in a modulus, and we're given the remainder of dividing `target` by that modulus.
Luckily for us, we know that `target` lies on the interval 1 \<= target \<= n, so if we send in any number greater than or equal to n, the remainder we're given will just be `target`, which we can then send in to get the flag.

You could honestly do that process by hand since it's not too involved, but here's the solve script I used anyways :)

```python
from pwn import *

if __name__ == "__main__":
    context.log_level = "error"
    io = remote("lac.tf", 31110)

    # recover n
    p = int(io.recvline())
    q = int(io.recvline())
    n = p*q
    print(f"{n = }")

    # send large modulus to recover target
    # n+1 is used to properly handle the (vanishingly rare) case where target == n
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"modulus here: ", str(n+1).encode())
    target = io.recvline(False)

    # guess target and get the flag :)
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"guess here: ", target)
    print(io.recvuntil(b"}").decode())
```

Running it does indeed give us the flag:

```shell
$ python not_lazy_enough.py
n = 55692639196434254870264721491584159007828403474043117364721365870540043640047896698230135617184107916980985178902495205386506386854446624575893254769112978552738903494563325064376028278135767160979917616792783984064359383528247873329988495738807379866296759366429252849512875467895324841499781477708501262753
lactf{too_lazy_to_bound_the_modulus}
```
