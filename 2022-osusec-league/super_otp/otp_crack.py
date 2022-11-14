from pwn import *

from base64 import b64decode
import functools

# Stolen shamelessly from super_otp.py
def xor_bytes(b1:bytes, b2:bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, b2))

def fetch_otp(server, length) -> bytes:
    # Ignore prompt
    server.recvline()

    # Send same number of null bytes as flag length
    server.sendline(b"\x00" * length)

    # Ignore message about response being in base64
    server.recvline()

    # Strip the newline off of the received input & decode it
    return b64decode(server.recvline().strip())

if __name__ == "__main__":
    otp_server = remote("chal.ctf-league.osusec.org", 22445)

    # Ignore initial explanation message
    otp_server.recvline()

    # Receive & strip newline from encrypted flag
    flag = otp_server.recvline().strip()
    binary_flag = b64decode(flag)
    flag_len = len(binary_flag)

    print(f"encrypted flag (base64): {flag}")

    # Fetch the three OTPs and XOR them back into the super OTP
    otps = [fetch_otp(otp_server, flag_len) for _ in range(3)]
    super_otp = functools.reduce(xor_bytes, otps)

    # Decrypt the flag :)
    flag_decrypted = xor_bytes(binary_flag, super_otp)
    print(f"decrypted flag: {flag_decrypted}")