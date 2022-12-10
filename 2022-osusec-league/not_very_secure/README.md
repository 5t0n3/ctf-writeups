# not_very_secure

> RSA is a Really Secure Algorithm when used correctly. Here it isn't...

## Solution

We're provided with some information right off the bat:

```text
N: 4777805290463711026025530760997341215210485822996023118027623646117723191500719041518959799725566059428554801696706296582581695310479723757513175744877550944865803932093280029829366260565558093216826465112625300559200066643691564027696443851265545121928906737207782768662058439770013206909817779391660295937449587329571897991774335797160269734366923630381643014686236264025697244867112514868261836050971328293396853758777800827880833925181379721342353017797906724353979687889041742404605317986943822242304998601391883361325971913770331586178253989604353973935125868269417765045588838194560248401591031608094124211
E: 11
The encrypted flag in base 64: SOIBDfTgLGiKSogVGF1ell/EJNthxiL+rP7QjMjg4j4l58piOWEnF7oDQMAc3y3QhXHBC4RU4TsemCENzTae1zpBJ5W3XmwbBvF8ot19E28FVBjZLE5uUk7caH8b1q/2GhZQnLNtfHHHZzlFcvg5ENiA1iqlpxoO+VLcgLqs2zpDFihamaGLOA0I1yC/vwtn79rgg3UMJVikFqlrBMdN2h3WuMKwPB9vCfjXI+XrhPDRr96rO5xKVPzQvjJSu4Rz3jsKbz0WmnNE7lmNSZDi+P+KKBFZffJWKRaIwEWJQl8y/4yFjz1rHhX/ta2mPVEEBfO8sM/oc3UPp8E2BKAB
```

Huh, that seems like a really small value for the encryption exponent (I think 65537 is normally what keys default to).
Let's check out how the private key used to encrypt the flag was generated in the [provided Python script](provided/not_very.py):

```python
# relevant imports (lines 2-3)
from secrets import randbits
from sympy import nextprime, randprime

# --snip--

# lines 40-53
# For challenge
def genKeysChall():
	p = getPrime()
	q = nextprime(p, randbits(4))
	n = p*q
	phi = (p-1)*(q-1)
	
	e = 3
	while (phi % e) == 0:
		e = nextprime(e)
		
	d = pow(e, -1, phi)
	
	return n, e, d
```

According to [Python's documentation](https://docs.python.org/3/library/secrets.html#secrets.randbits), the `randbits()` function does what it sounds like: it generates an integer with the provided number of bits. In this case that number of bits is 4, meaning the result of the `randbits(4)` call will be an integer between 0 and 2⁴ - 1, or 15.
[`nextprime(n, ith)`](https://docs.sympy.org/latest/modules/ntheory.html#sympy.ntheory.generate.nextprime), on the other hand, returns the `i`th prime after its first argument.
This means that the p and q factors for this private key are within 15 primes of each other, which isn't a good sign for whoever wanted to keep the flag encrypted :)

Because the two primes are so close together, they must also both be somewhat close to the square root of n, the public modulus that we're provided:

```shell
Python 3.10.8 (main, Oct 11 2022, 11:35:05) [GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import math
>>> math.isqrt(4777805290463711026025530760997341215210485822996023118027623646117723191500719041518959799725566059428554801696706296582581695310479723757513175744877550944865803932093280029829366260565558093216826465112625300559200066643691564027696443851265545121928906737207782768662058439770013206909817779391660295937449587329571897991774335797160269734366923630381643014686236264025697244867112514868261836050971328293396853758777800827880833925181379721342353017797906724353979687889041742404605317986943822242304998601391883361325971913770331586178253989604353973935125868269417765045588838194560248401591031608094124211)
2185819134892846303821484490388227753775741420901635959367600777971553072407693332368773919893090017733984107800876486624486835453612086472018692822442081563571586146861538533711213420094496550663536642467196540252278533502878750308803648101306206293944992935890890181966725031135636586026284799457426195405
```

Still an insanely large number but we're getting closer :)
I decided to test the 15 primes after this square root just in case, although that was probably overkill. This is made really easy with sympy's `nextprime()` function that was also used to generate the key.
All we need to check for each prime is if it evenly divides the public modulus `n`, or in other words that `n % p` is 0. From there, wecan get the value of the other factor by dividing n by p:

```python
from sympy import nextprime

import math

N = 4777805290463711026025530760997341215210485822996023118027623646117723191500719041518959799725566059428554801696706296582581695310479723757513175744877550944865803932093280029829366260565558093216826465112625300559200066643691564027696443851265545121928906737207782768662058439770013206909817779391660295937449587329571897991774335797160269734366923630381643014686236264025697244867112514868261836050971328293396853758777800827880833925181379721342353017797906724353979687889041742404605317986943822242304998601391883361325971913770331586178253989604353973935125868269417765045588838194560248401591031608094124211

SQRT_N = math.isqrt(N)
p = SQRT_N

# check if any of the next 15 primes evenly divide n
for _ in range(15):
    p = nextprime(p)
    if N % p == 0:
        break

# p * q = n -> q = n / p
# note that the double slash is integer division (as opposed to floating point division)
q = N // p

print(f"p = {p}")
print(f"q = {q}")
print(f"factors match n: {p * q == N}")
```

Running that program yields the following result:

```shell
$ python find_factors.py
p = 2185819134892846303821484490388227753775741420901635959367600777971553072407693332368773919893090017733984107800876486624486835453612086472018692822442081563571586146861538533711213420094496550663536642467196540252278533502878750308803648101306206293944992935890890181966725031135636586026284799457426196581
q = 2185819134892846303821484490388227753775741420901635959367600777971553072407693332368773919893090017733984107800876486624486835453612086472018692822442081563571586146861538533711213420094496550663536642467196540252278533502878750308803648101306206293944992935890890181966725031135636586026284799457426194231
factors match n: True
```

Neat! So now that we have our factors, we can calculate the decryption exponent by the relationship shown in the `genKeysChall()` function:

```python
def genKeysChall():
    # --snip--
    phi = (p-1)*(q-1)

    # --snip--

    d = pow(e, -1, phi)
```

You can read more about why this works on [the Wikipedia page about RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation) (note that they use Carmichael's totient function instead of [Euler's totient function](https://en.wikipedia.org/wiki/Euler's_totient_function) like we use here, although for our purposes they are interchangeable).
It essentially boils down to e (the encryption exponent) and d (the decryption exponent) being modular inverses with respect to n, i.e. (mᵉ)ᵈ ≡ m mod n, where m is the message that you are trying to encrypt.
This property is the basis of how RSA encryption works: because n is (normally) extremely diffcult to factor due to its factor primes p and q being relatively far apart, it would then extremely difficult for an attacker to find the decryption exponent from a given public key.
Obiously this security is kind of thrown out the window in this case because p and q are so close together, but at least that lets us get the flag :)

Anyways tangent over, let's get to decrypting that flag:

```python
# this is meant to be appended to the above code that finds the factors of N :)

from base64 import b64decode

E = 11
FLAG_BASE64 = "SOIBDfTgLGiKSogVGF1ell/EJNthxiL+rP7QjMjg4j4l58piOWEnF7oDQMAc3y3QhXHBC4RU4TsemCENzTae1zpBJ5W3XmwbBvF8ot19E28FVBjZLE5uUk7caH8b1q/2GhZQnLNtfHHHZzlFcvg5ENiA1iqlpxoO+VLcgLqs2zpDFihamaGLOA0I1yC/vwtn79rgg3UMJVikFqlrBMdN2h3WuMKwPB9vCfjXI+XrhPDRr96rO5xKVPzQvjJSu4Rz3jsKbz0WmnNE7lmNSZDi+P+KKBFZffJWKRaIwEWJQl8y/4yFjz1rHhX/ta2mPVEEBfO8sM/oc3UPp8E2BKAB"

# find the decryption exponent
phi = (p - 1) * (q - 1)
d = pow(E, -1, phi)

# decode & decrypt the data by just doing the encryption in reverse
decoded_data = b64decode(FLAG_BASE64)
dataInt = int.from_bytes(decoded_data, byteorder="little")
decrypted = pow(dataInt, d, N)
flag = decrypted.to_bytes(decrypted.bit_length()//8+1, "little")

print()
print("Flag: " + flag.decode())
```

And now, running [that full program](./break_rsa.py):

```shell
$ python break_rsa.py
p = 2185819134892846303821484490388227753775741420901635959367600777971553072407693332368773919893090017733984107800876486624486835453612086472018692822442081563571586146861538533711213420094496550663536642467196540252278533502878750308803648101306206293944992935890890181966725031135636586026284799457426196581
q = 2185819134892846303821484490388227753775741420901635959367600777971553072407693332368773919893090017733984107800876486624486835453612086472018692822442081563571586146861538533711213420094496550663536642467196540252278533502878750308803648101306206293944992935890890181966725031135636586026284799457426194231
factors match n: True

Flag: osu{d0n't_r011_y0ur_0vvn_vvay}
```

And there's our flag! Make sure if you ever generate RSA keys that you use actually random prime numbers instead of generating them like in this case, or just go with [elliptic curve keys](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) since they tend to be smaller while being similarly secure :)
