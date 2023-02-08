from pwn import *
import numpy as np
import galois

import ctypes

# taken from params.h
PUB_N = 112
PUB_M = 44
_O = PUB_M
_V = PUB_N - _O

# consequence of GF256 being used
O_BYTE = _O
V_BYTE = _V

# taken from vinaigrette.py
CRYPTO_SECRETKEYBYTES = 237912
CRYPTO_PUBLICKEYBYTES = 43576
CRYPTO_BYTES = 128

libpqov = ctypes.CDLL("./libpqov.so")

# polynomial taken from page 5 of paper
GF = galois.GF(256, irreducible_poly="x^8+x^4+x^3+x+1")


def sign_message(msg):
    global GF
    p = remote("mc.ax", 31337)

    p.sendlineafter(b"order? ", msg)
    p.recvuntil(b"here it is: ")

    # signature is prepended with message; the signature itself is only the last 128 bytes
    response = bytes.fromhex(p.recvlineS(keepends=False))
    full_sig = list(response)[-CRYPTO_BYTES:]

    # signature is (v + Ox) || x || salt; salt doesn't matter
    return GF(full_sig[:V_BYTE]), GF(full_sig[V_BYTE : V_BYTE + O_BYTE])


def forge_sk(pk_seed, t1):
    sk = ctypes.create_string_buffer(CRYPTO_SECRETKEYBYTES)
    # custom function; see README
    assert libpqov.expand_sk_from_t1(sk, pk_seed, t1) == 0
    return sk


def sign(sk, m):
    # adapted from vinaigrette.py (m doesn't technically need a string buffer)
    mlen = ctypes.c_size_t(len(m))
    sm = ctypes.create_string_buffer(len(m) + CRYPTO_BYTES)
    smlen = ctypes.c_size_t(0)
    libpqov.crypto_sign(sm, ctypes.pointer(smlen), m, mlen, sk)
    return bytes(sm)


if __name__ == "__main__":
    context.log_level = "error"

    with open("provided/pk.bin", "rb") as k:
        cpk = k.read()

    # recovery of O matrix/secret key
    message = b"bogos binted?"
    Ox = []
    X = []

    s0, x0 = sign_message(message)
    for i in range(O_BYTE):
        print(f"signing message {i+1}/{_O}")
        s, x = sign_message(message)
        Ox.append(s - s0)
        X.append(x - x0)

    Ox = GF(Ox)
    X = GF(X)

    O = np.linalg.solve(X, Ox)
    t1 = O.tobytes()

    sk = forge_sk(cpk[:16], t1)

    # signature forgery
    secret_message = b"the vinaigrette recipe"
    auth = sign(sk, secret_message)
    p = remote("mc.ax", 31337)
    p.sendlineafter(b"order", secret_message)
    p.sendlineafter(b"Authorization: ", auth.hex().encode())

    # flag!
    flag = p.recvlineS(keepends=False)
    print(flag)
