from pwn import *

if __name__ == "__main__":
    context.log_level = "error"
    io = remote("lac.tf", 31110)

    # recover n
    p = int(io.recvline())
    q = int(io.recvline())
    n = p*q
    print(f"{n = }")

    # send large modulus to recover target
    # n+1 is used to properly handle the (vanishingly rare) case where target == n
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"modulus here: ", str(n+1).encode())
    target = io.recvline()

    # guess target and get the flag :)
    io.sendlineafter(b">> ", b"2")
    io.sendafter(b"guess here: ", target)
    print(io.recvuntil(b"}").decode())