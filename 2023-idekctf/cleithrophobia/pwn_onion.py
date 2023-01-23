from pwn import *

from Crypto.Util.Padding import unpad

class Onion(bytes):
    """bytes subtype with some convenience features"""
    @property
    def iv(self):
        return self[-1]

    def rev_iter_blocks(self):
        """iterates over the encrypted blocks in reverse"""
        for i in reversed(range(len(self))):
            yield self[i]

    def __len__(self):
        """number of encrypted blocks in the wrapped ciphertext"""
        return super().__len__() // 16 - 1

    def __getitem__(self, key):
        # the `or None` handles the case where key is -1
        bs = super().__getitem__(slice(key*16, (key+1)*16 or None))
        return type(self)(bs)

    def __xor__(self, other):
        return type(self)(s ^ o for s, o in zip(self, other, strict=True))

def onion_encrypt(proc, message):
    proc.sendlineafter(b"> (hex) ", message.hex().encode())
    proc.recvuntil(b"|\n|   ")
    return Onion.fromhex(proc.recvlineS(keepends=False))

def encrypt_block(proc, block):
    payload = bytes(32) + block
    result = onion_encrypt(proc, payload)
    return result[1]

def decrypt_block(proc, block, enc_padding):
    payload = block ^ enc_padding
    result = onion_encrypt(proc, payload)
    return result[1] ^ result.iv

def decrypt_flag(proc, flag):
    """unwraps the onion of whatever encryption scheme this is :)"""
    # start with IV
    prev_xor = flag.iv

    # xor our way to the first block :)
    inner = []
    for block in flag.rev_iter_blocks():
        next_dec = block ^ prev_xor
        prev_xor = encrypt_block(proc, next_dec)
        inner.append(prev_xor)

    # decryption requires an encrypted padding block
    enc_padding = encrypt_block(proc, b"\x10"*16)

    # decrypt our way to the plaintext
    prev_block = flag.iv
    decrypted_blocks = []
    for block in reversed(inner):
        decrypted = decrypt_block(proc, block ^ prev_block, enc_padding)
        decrypted_blocks.append(decrypted)
        prev_block = decrypted

    # decrypted flag is in flag{} format, not idek{}
    wrong_prefix = unpad(b"".join(decrypted_blocks), 16).decode()
    return wrong_prefix.replace("flag", "idek")


if __name__ == "__main__":
    context.log_level = "error"

    # p = process(["python", "cleithrophobia.py"])
    p = remote("cleithrophobia.chal.idek.team", 1337)

    p.recvuntil(b"flag = ")
    flag_enc = Onion.fromhex(p.recvlineS(keepends=False))

    flag_decrypted = decrypt_flag(p, flag_enc)
    print(f"Decrypted flag: {flag_decrypted}")
