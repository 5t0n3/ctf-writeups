# crypto/keyexchange (120 points/118 solves)

> Diffie-Hellman is secure right

Provided:
- [`challenge.py`](provided/challenge.py)
- [`Dockerfile`](provided/Dockerfile)

Summary: Flag is xored with number we have some control over; 1 is really convenient as an exponent :)

## Solution

The program running on the server that we're provided isn't long at all:

```python
#!/opt/homebrew/bin/python3

from Crypto.Util.strxor import strxor
from Crypto.Util.number import *
from Crypto.Cipher import AES

n = getPrime(512)

s = getPrime(256)

a = getPrime(256)
# n can't hurt me if i don't tell you
print(pow(s, a, n))
b = int(input("b? >>> "))

secret_key = pow(pow(s, a, n), b, n)

flag = open('/flag', 'rb').read()

key = long_to_bytes(secret_key)
enc = strxor(flag + b'\x00' * (len(key) - len(flag)), key)
print(enc.hex())
```

I'm not sure why AES is imported haha :)

It looks like $n$, $s$, and $a$ are all random primes of varying bit lengths.
We're given $s^a \mod n$ and are allowed to input an exponent $b$.
The integer $s^{ab} \mod n$ is then converted to a byte representation and xored with the flag, with the hex result of that being the last thing we were provided.

My first thought was to provide an exponent of zero, but as it turns out pycryptodome's `strxor` requires its inputs to be the same length, which is impossible if `key` is 1 due to how `long_to_bytes` works.
After some profound thought I realized that if we provide 1 as an exponent, `key` would just be the byte representation of $s^{a(1)} \mod n = s^a \mod n$ which is something we can easily find from what we're provided :)

My [solve script](pwn_kex.py) also ended up being pretty short, so here it is in its entirety:

```python
from pwn import *

from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes

if __name__ == "__main__":
    context.log_level = "error"
    io = remote("keyexchange.wolvctf.io", 1337)

    io.recvline()
    s_a = int(io.recvlineS())

    io.sendlineafter(b"b? >>> ", b"1")

    s_a_bytes = long_to_bytes(s_a)
    flag = bytes.fromhex(io.recvlineS())
    print("flag:", strxor(flag, s_a_bytes).rstrip(b"\0").decode())
```

It does of course give us the flag:

```shell
$ python pwn_kex.py
flag: wctf{m4th_1s_h4rd_but_tru5t_th3_pr0c3ss}
```

Math really is hard sometimes, but it's definitely less hard when you're dealing with exponents of 1 :)