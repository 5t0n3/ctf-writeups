from pwn import *


if __name__ == "__main__":
    context.log_level = "error"
    conn = remote("lac.tf", 31190)

    max_six_factors = 0

    print("Guessing bits...")
    print()
    for i in range(150):
        conn.recvuntil(b"c =  ")
        c = int(conn.recvline())

        # check multiplicity of 6 as a factor
        divisions = 0
        while c % 6 == 0:
            c //= 6
            divisions += 1

        # odd divisions -> multiplied by a, even -> not multiplied
        bit = divisions % 2
        conn.sendlineafter(b"guess? ", str(bit).encode())

        # curiosity :)
        max_six_factors = max(max_six_factors, divisions)

    print(conn.recvuntil(b"}").decode())
    print()
    print(f"Maximum number of 6 factors: {max_six_factors}")
