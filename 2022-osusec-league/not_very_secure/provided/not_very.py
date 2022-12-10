#!/usr/bin/python3
from secrets import randbits
from sympy import nextprime, randprime
from base64 import b64encode
from flag import FLAG

MAX_LENGTH = 60

# Get a random large prime
def getPrime():
    return randprime(1, 2**1024)


# Regular keygen
def genKeys():
    p = getPrime()
    q = getPrime()
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while (phi % e) == 0:
        e = nextprime(e)

    d = pow(e, -1, phi)

    return n, e, d


# Using a single prime number, because half the generation time
def genKeysEx():
    n = randprime(1, 2**2048)
    phi = n - 1

    e = 3
    while (phi % e) == 0:
        e = nextprime(e)

    d = pow(e, -1, phi)

    return n, e, d


# For challenge
def genKeysChall():
    p = getPrime()
    q = nextprime(p, randbits(4))
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while (phi % e) == 0:
        e = nextprime(e)

    d = pow(e, -1, phi)

    return n, e, d


def enc(key, data):
    dataInt = int.from_bytes(data, "little")
    encData = pow(dataInt, key[1], key[0])
    return encData.to_bytes(encData.bit_length() // 8 + 1, "little")


if __name__ == "__main__":

    n, e, d = genKeysChall()

    enc_flag = enc((n, e), FLAG.encode())

    # print out the encrypted flag
    print("N:")
    print(n)
    print("E:")
    print(e)
    print("The encrypted flag in base 64:")
    print(b64encode(enc_flag).decode())
