from pwn import *

from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes

if __name__ == "__main__":
    context.log_level = "error"
    io = remote("keyexchange.wolvctf.io", 1337)

    io.recvline()
    s_a = int(io.recvlineS())

    io.sendlineafter(b"b? >>> ", b"1")

    s_a_bytes = long_to_bytes(s_a)
    flag = bytes.fromhex(io.recvlineS())
    print("flag:", strxor(flag, s_a_bytes).rstrip(b"\0").decode())
