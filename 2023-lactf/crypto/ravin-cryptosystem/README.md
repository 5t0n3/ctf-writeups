# crypto/ravin-cryptosystem (123 solves/425 points)

> I don't really understand why people choose big numbers that can't be factored. No one has been able to crack my RSA implementation even though my modulus is factorable. It should just be normal RSA??? All I did was make it faster. I've asked my friends and the only feedback I've gotten so far are rave reviews about how secure my algorithm is. Hmm, maybe I'll name it the Ravin Cryptosystem. There better not be anyone with a similar idea.

Provided:

- [`ravin.py`](ravin.py)
- [`output.txt`](output.txt)

## Solution

Since `n`'s factors are pretty small at 100 bits each, factoring `n` isn't actually too bad:

```python
sage: n = 996905207436360486995498787817606430974884117659908727125853
sage: p, q = n.prime_factors(); (p, q)
(861346721469213227608792923571, 1157379696919172022755244871343)
```

For some reason, though, regular RSA encryption (i.e. inverting e mod the totient of n) doesn't work:

```python
sage: e = 65537
sage: c = 375444934674551374382922129125976726571564022585495344128269
sage: d = inverse_mod(e, (p-1)*(q-1))
sage: m = pow(c, d, n)
sage: int(m).to_bytes(length=m.bit_length()//8 + 1, byteorder="big")
b'uFU\xa8Os\xd8\xa3\xeb\x8b]\xfd\xbb4d\x0c\xed\xeacc%r\xa1\xa0\x8c'
```

The provided program seems to do all of the steps involved in RSA encryption correctly, although it uses a custom `fastpow` function which looked interesting:

```python
def fastpow(b, p, mod):
    # idk this is like repeated squaring or something i heard it makes pow faster
    a = 1
    while p:
        p >>= 1
        b = (b*b)%mod
        if p&1:
            a = (a*b)%mod
    return a
```

I'd heard of repeated squaring before, so I figured I'd check out the Wikipedia page about [modular exponentiation](https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode) for reference and found this pseudocode:

```
function modular_pow(base, exponent, modulus) is
    if modulus = 1 then
        return 0
    Assert :: (modulus - 1) * (modulus - 1) does not overflow base
    result := 1
    base := base mod modulus
    while exponent > 0 do
        if (exponent mod 2 == 1) then
            result := (result * base) mod modulus
        exponent := exponent >> 1
        base := (base * base) mod modulus
    return result
```

Obviously `fastpow` doesn't have any assertions or anything, but one difference I noticed was that the exponent was right-shifted *before* the multiplication process which was interesting.
Repeated squaring does what it sounds like (repeated squaring) but also multiplies the result by the base whenever the exponent has a 1 bit in the ones place, if that makes sense.

On a completely unrelated note, let's check out the binary representation of 65537, our encryption exponent :)

```python
sage: bin(65537)
'0b10000000000000001'
```

It turns out that 65537 only has two 1 bits in its binary representation, meaning that under normal circumstances the result/base multiplication would happen twice.
However, since the exponent is right-shifted first *before* doing anything, it only happens once, meaning that the result of `fastpow` with 65537 as an exponent will just lead to literal repeated squaring.
The exact number of squares will just be the log base 2 of 65537 - 1 = 65536 (since the ones bit gets shifted away immediately):

```python
sage: log(65536, 2)
16
```

Note that this effective power of 65536 isn't invertible mod the totient of `n`, meaning normal RSA decryption won't work in this case:

```python
sage: inverse_mod(65536, (p-1)*(q-1))
# snip
ZeroDivisionError: inverse of Mod(65536, -1157379696919172022755244871342) does not exist
```

There is still hope to reverse the encryption process, though, through sage's `nth_root` function.
Because have `n`'s factors, we can use the Chinese Remainder Theorem to speed up the computation of those 16 square roots.

Here's what my solve script ended up looking like:

```python
n = 996905207436360486995498787817606430974884117659908727125853
e = 65537
c = 375444934674551374382922129125976726571564022585495344128269

# p, q = n.prime_factors()
p, q = [861346721469213227608792923571, 1157379696919172022755244871343]

MP = Zmod(p)
MQ = Zmod(q)

# undo the repeated squaring
m = c
for _ in range(16):
    mp = ZZ(MP(m).nth_root(2))
    mq = ZZ(MQ(m).nth_root(2))
    m = crt([mp, mq], [p, q])

# convert the flag back to a string :)
print(int(m).to_bytes(m.bit_length()//8+1, byteorder="big").decode())
```

Running it gives us the flag for real this time :)

```shell
$ sage unravin.sage
lactf{g@rbl3d_r6v1ng5}
```

I'm pretty sure the name of this challenge was a reference to the [Rabin cryptosystem](https://en.wikipedia.org/wiki/Rabin_cryptosystem), which is similar to RSA but with a public exponent of 2.
`n`'s factors must also have certain properties for it to work properly.
Again because the exponent is even, it's not invertible mod the totient of `n`, so you have to do decryption slightly differently.

Anyways, enough of a tangent.
This definitely wasn't normal RSA but it also wasn't as secure as its maker made it out so sound :)
