import os

os.environ["PWNLIB_NOTERM"] = "1"

from pwn import *

mod_ring = Zmod(95)


def stov(s):
    global mod_ring
    return vector(mod_ring, [ord(c) - 32 for c in s])


def vtos(v):
    return "".join([chr(ZZ(v_i) + 32) for v_i in v])


if __name__ == "__main__":
    context.log_level = "error"
    conn = remote("lac.tf", int(31140))

    # Get two (encrypted) halves of first fake flag
    conn.recvline()  # "On the hill lies a stone. It reads:"
    f1 = conn.recvlineS(False)
    f2 = conn.recvlineS(False)

    pt = []
    ct = []

    # Get plaintext -> ciphertext mappings to recover A matrix
    print("Querying oracle...")
    for _ in range(10):
        h1 = random_vector(mod_ring, 20)
        h2 = random_vector(mod_ring, 20)

        conn.sendlineafter(b"guess: ", (vtos(h1) + vtos(h2)).encode())
        conn.recvline()

        c1 = stov(conn.recvlineS(False))
        c2 = stov(conn.recvlineS(False))

        pt.extend([h1, h2])
        ct.extend([c1, c2])

    pt = matrix(mod_ring, pt).T
    ct = matrix(mod_ring, ct).T

    # Solve linear equations set up from random inputs
    A = pt.solve_left(ct) # equivalent to ct * pt^-1

    # Get and encrypt second fake flag
    conn.recvuntil(b"following:\n")
    fake2 = conn.recvlineS(False)

    f3_dec, f4_dec = fake2[:20], fake2[20:]
    f3 = A * stov(f3_dec)
    f4 = A * stov(f4_dec)

    # Send encrypted flag halves
    conn.sendlineafter(b"half: ", vtos(f3).encode())
    conn.sendlineafter(b"half: ", vtos(f4).encode())

    # Flag!
    print(conn.recvuntil(b"}").decode())
