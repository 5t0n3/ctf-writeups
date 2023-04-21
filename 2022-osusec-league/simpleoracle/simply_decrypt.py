from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.padding import PKCS7
from pwn import *


def oracle(io, iv, block):
    encoded = b64encode(iv + block)

    io.sendline(encoded)

    resp = io.recvline()
    return b"SUCCESS" in resp


def bruteforce_block(io, orig_iv, block):
    known_bytes = bytearray(16)

    # hack to avoid blocks that already have valid padding
    # technically this breaks blocks that actually have 1 byte of padding but
    # that doesn't matter for this challenge
    skip = True

    # go over full block
    for pos in range(1, 17):
        # correct end padding because yeah
        end_padding = bytes(16 - (pos - 1)) + bytes([pos] * (pos - 1))

        # xor iv with known bytes + make known stuff valid
        # this makes finding the known byte a bit easier :)
        mod_iv = xor(known_bytes, orig_iv, end_padding)

        # brute force the byte :(
        # also fun fact: Python's boolean type is just a subclass of integers :)
        for cand in range(0 + skip, 256):
            # we do a little IV tampering
            this_iv = bytearray(mod_iv)
            this_iv[-pos] ^= cand

            if oracle(io, this_iv, block):
                print(f"success! {cand = }")
                # xor padding byte with the candidate to recover the plaintext block
                known_bytes[-pos] = cand ^ pos
                break

        # </hack>
        skip = False

    return known_bytes


if __name__ == "__main__":
    # io = process(["python", "simple_oracle/server.py"])
    io = remote("chal.ctf-league.osusec.org", 1347)

    # get encrypted flag :)
    io.recvuntil(b"is: ")
    enc_flag = b64decode(io.recvline())

    # decipher each block one by one
    flag_dec = bytes()
    for idx in range(0, len(enc_flag) - 16, 16):
        iv = enc_flag[idx : idx + 16]
        block = enc_flag[idx + 16 : idx + 32]

        decrypted = bruteforce_block(io, iv, block)
        flag_dec += decrypted

    # remove padding from flag before printing
    unpadder = PKCS7(128).unpadder()
    flag = unpadder.update(flag_dec) + unpadder.finalize()
    print("flag:", flag.decode())
