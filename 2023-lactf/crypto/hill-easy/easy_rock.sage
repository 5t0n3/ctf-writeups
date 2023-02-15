import os
os.environ["PWNLIB_NOTERM"] = "1"

from pwn import *

mod_ring = Zmod(95)

def stov(s):
    global mod_ring
    return vector(mod_ring, [(ord(c)-32) for c in s])

def vtos(v):
    return ''.join([chr(ZZ(v_i)+32) for v_i in v])

if __name__ == "__main__":
    context.log_level = "error"
    conn = remote("lac.tf", int(31140))

    conn.recvline() # "On the hill lies a stone."
    f1 = conn.recvlineS(False)
    f2 = conn.recvlineS(False)

    vecs = []

    # Recover columns of A matrix in pairs
    print("Querying oracle")
    for i in range(0, 20, 2):
        # ! -> 1 after subtracting 32 from ASCII codepoint
        h1 = " "*i + "!" + " "*(20-i-1)
        h2 = " "*(i+1) + "!" + " "*(20-i-2)

        conn.sendlineafter(b"guess: ", (h1 + h2).encode())

        conn.recvline() # Incorrect:
        c1 = stov(conn.recvlineS(False))
        c2 = stov(conn.recvlineS(False))

        vecs.extend([c1, c2])

    A = matrix(mod_ring, vecs).T
    A_inv = A.inverse()

    # Recover first fake flag because why not
    fake1_dec = vtos(A_inv*stov(f1)) + vtos(A_inv*stov(f2))
    print()
    print(f"Fake flag 1 (encrypted): {f1 + f2}")
    print(f"Fake flag 1 (decrypted): {fake1_dec}")
    print()
    
    # Receive and encrypt the second fake flag
    conn.recvuntil(b"following:\n")
    fake2 = conn.recvlineS(False)
    print(f"Fake flag 2: {fake2}")
    
    f3_dec, f4_dec = fake2[:20], fake2[20:]
    
    f3 = vtos(A * stov(f3_dec))
    f4 = vtos(A * stov(f4_dec))
    
    print(f"Fake flag 2 (encrypted): {f3 + f4}")
    
    conn.sendlineafter(b"half: ", f3.encode())
    conn.sendlineafter(b"half: ", f4.encode())
    print(conn.recvuntil(b"}").decode()) # "The text on the stone..."
