from pwn import *

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.strxor import strxor

message = b"heythisisasupersecretsupersecret"
header = b"WolvCTFCertified"


def GF_mult(x, y):
    product = 0
    for i in range(127, -1, -1):
        product ^= x * ((y >> i) & 1)
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    return product


def H_mult(H, val):
    product = 0
    for i in range(16):
        product ^= GF_mult(H, (val & 0xFF) << (8 * i))
        val >>= 8
    return product


def GHASH(H, A, C):
    C_len = len(C)
    A_padded = bytes_to_long(A + b"\x00" * (16 - len(A) % 16))
    if C_len % 16 != 0:
        C += b"\x00" * (16 - C_len % 16)

    tag = H_mult(H, A_padded)

    for i in range(0, len(C) // 16):
        tag ^= bytes_to_long(C[i * 16 : i * 16 + 16])
        tag = H_mult(H, tag)

    tag ^= bytes_to_long(
        (8 * len(A)).to_bytes(8, "big") + (8 * C_len).to_bytes(8, "big")
    )
    tag = H_mult(H, tag)

    return tag


if __name__ == "__main__":
    context.log_level = "error"
    # io = process(["python", "server.py"])
    io = remote("galois.wolvctf.io", 1337)

    # initial encryption: all Fs to recover Enc(0)
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"IV (hex) > ", b"f" * 32)
    io.sendlineafter(b"Plaintext (hex) > ", b"0" * (32 * 3))

    io.recvuntil(b"CT: ")
    ct_fs = bytes.fromhex(io.recvlineS())

    # recover "nonce"/H key & counter blocks
    enc_0 = ct_fs[:16]
    enc_1to2 = ct_fs[16:]

    # signature forgery :)
    ct = strxor(message, enc_1to2)
    new_tag = strxor(enc_0, long_to_bytes(GHASH(bytes_to_long(enc_0), header, ct)))

    # we do a little decryption
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"IV (hex) > ", b"0" * 32)
    io.sendlineafter(b"Ciphertext (hex) > ", ct.hex().encode())
    io.sendlineafter(b"Tag (hex) > ", new_tag.hex().encode())
    print("Flag:", io.recvuntil(b"}").decode())
