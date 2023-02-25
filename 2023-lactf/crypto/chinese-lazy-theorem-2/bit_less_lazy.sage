import os
os.environ["PWNLIB_NOTERM"] = "1"

from pwn import *

def get_modulus(conn, num):
    conn.sendlineafter(b">> ", b"1")
    conn.sendlineafter(b"here: ", str(num).encode())
    res = ZZ(conn.recvline())
    conn.recvline()
    return res

def guess(conn, num):
    conn.sendlineafter(b"here: ", str(num).encode())
    res = conn.recvlineS(False)
    if res != "nope":
        return res

if __name__ == "__main__":
    context.log_level = "error"
    conn = remote("lac.tf", int(31111))

    # recover n and its factors
    p = ZZ(conn.recvline())
    q = ZZ(conn.recvline())
    n = p * q * 2*3*5

    # get remainders from division by p/q
    modp = get_modulus(conn, p)
    modq = get_modulus(conn, q)
    print(f"{modp = }")
    print(f"{modq = }")

    print("guessing 30 remainder...")
    conn.sendlineafter(b">> ", b"2")
    for i in range(30):
        g = crt([modp, modq, i], [p, q, 30])
        res = guess(conn, g)
        if res is not None:
            print(res)
            break