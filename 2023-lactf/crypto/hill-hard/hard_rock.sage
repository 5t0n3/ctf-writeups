import os
os.environ["PWNLIB_NOTERM"] = "1"

from pwn import *

mod_ring = Zmod(95)


def stov(s):
    global mod_ring
    return vector(mod_ring, [(ord(c) - 32) for c in s])


def vtos(v):
    return "".join([chr(ZZ(v_i) + 32) for v_i in v])


def server_encrypt(conn, vecstr):
    conn.sendlineafter(b"guess: ", vecstr.encode())
    res = conn.recvlineS(keepends=False)
    return stov(res)


if __name__ == "__main__":
    context.log_level = "error"

    # conn = process(["python", "chall.py"])
    conn = remote("lac.tf", int(31141))

    conn.recvline()  # "On the hill lies a stone. It reads:"
    fake1_enc = conn.recvlineS(keepends=False)
    fake1_vec = stov(fake1_enc)
    print(f"fake flag 1 (encrypted): {fake1_enc}")

    # first get a baseline
    base = server_encrypt(conn, "lactf{" + ("@" * 13) + "}")

    vecs = []

    # recover the columns of A corresponding to the random letters
    for i in range(13):
        payload = "lactf{" + ("@" * i) + "`" + ("@" * (12 - i)) + "}"
        result = server_encrypt(conn, payload)
        this_vec = base - result
        vecs.append(this_vec)

    # enter the matrix
    A_part = matrix(mod_ring, vecs).T

    # used in recovering the lactf{} "contribution" to the matrix product during encryption
    vec_32 = vector(mod_ring, [32] * 13)
    inner_32 = A_part * vec_32

    # fake1_vec = A*(ord(c_i)-32) = A*ord(c_i) - A*[32]
    # outer = A*ord(c_i) - A_part*ord(c_j) for indices j inside lactf{...} (i.e. 6 to 18)
    outer_contribution = fake1_vec - base + inner_32
    
    # decrypt first flag while we're at it :)
    fake1 = A_part.solve_right(fake1_vec - outer_contribution)
    print(f"fake flag 1 (decrypted): lactf{{{vtos(fake1)}}}")
    print()

    # determine what we need to encrypt
    conn.recvuntil(b"Encrypt me:\n")
    fake2 = conn.recvlineS(keepends=False)
    fake2_vec = stov(fake2)
    print(f"fake flag 2: {fake2}")

    # we do a little encryption
    fake2_enc = vtos(A_part * fake2_vec[6:-1] + outer_contribution)
    print(f"fake flag 2 (encrypted): {fake2_enc}")
    conn.sendlineafter(b"guess: ", fake2_enc.encode())

    # "you can see what others cannot"
    print(conn.recvuntil(b"}").decode())
