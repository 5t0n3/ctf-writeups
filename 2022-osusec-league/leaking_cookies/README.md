# leaking_cookies

> Stack cookies are so powerful it doesn't matter what I do, you still won't be able to break it.

Provided: [`leaking-cookies`](leaking-cookies)

## Solution

As always, let's start of by looking at our binary:

```shell
$ file leaking-cookies
leaking-cookies: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=67ce06099fe49edb361ced8028caf7338fa7e2cd, with debug_info, not stripped

$ pwn checksec leaking-cookies
[*] '/path/to/leaking-cookies'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found # <--- this causes the below termination
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ ./leaking-cookies
Can you do anything with these: 0x7ffd17f6b500 0x1 0x900 0x400960 0x7fc29aee3d70 (nil) 0x7ffd17f6b648 0x7ffd17f6b530 0x14fa01f16b8b6c00 0x7ffd17f6b530 0x4008d0
Why are cookies delicious?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

So it looks like we can overflow the buffer our input is read to, but there's a stack cookie (or canary) placed on the stack to detect if we overwrite anything, for example by spamming a bunch of `A`s :)

We can check out a list of the functions actually defined in the binary in gdb/pwndbg:

```shell
pwndbg> info functions -n
All defined functions:

File src/leaking-cookies.c:
16:	void input_func();
25:	int main();
7:	void win();
```

Hmmm, that `win` function looks interesting :)
It's probably not a stretch to assume that our input is handled by `input_func`, so let's check out its disassembly:

```shell
pwndbg> disass input_func
Dump of assembler code for function input_func:
   0x0000000000400821 <+0>:	    push   rbp
   0x0000000000400822 <+1>:	    mov    rbp,rsp
   0x0000000000400825 <+4>:	    sub    rsp,0x20
   0x0000000000400829 <+8>:	    mov    rax,QWORD PTR fs:0x28
   0x0000000000400832 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400836 <+21>:	xor    eax,eax
   0x0000000000400838 <+23>:	lea    rax,[rbp-0x20]
   0x000000000040083c <+27>:	mov    rsi,rax
   0x000000000040083f <+30>:	lea    rdi,[rip+0x14a]        # 0x400990
   0x0000000000400846 <+37>:	mov    eax,0x0
   0x000000000040084b <+42>:	call   0x400650 <printf@plt>
   0x0000000000400850 <+47>:	lea    rdi,[rip+0x17b]        # 0x4009d2
   0x0000000000400857 <+54>:	call   0x400620 <puts@plt>
   0x000000000040085c <+59>:	mov    rdx,QWORD PTR [rip+0x20081d]        # 0x601080 <stdin@@GLIBC_2.2.5>
   0x0000000000400863 <+66>:	lea    rax,[rbp-0x20]
   0x0000000000400867 <+70>:	mov    esi,0xc8
   0x000000000040086c <+75>:	mov    rdi,rax
   0x000000000040086f <+78>:	call   0x400670 <fgets@plt>
   0x0000000000400874 <+83>:	mov    rax,QWORD PTR [rip+0x200805]        # 0x601080 <stdin@@GLIBC_2.2.5>
   0x000000000040087b <+90>:	mov    rdi,rax
   0x000000000040087e <+93>:	call   0x400680 <fflush@plt>
   0x0000000000400883 <+98>:	nop
   0x0000000000400884 <+99>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400888 <+103>:	xor    rax,QWORD PTR fs:0x28
   0x0000000000400891 <+112>:	je     0x400898 <input_func+119>
   0x0000000000400893 <+114>:	call   0x400630 <__stack_chk_fail@plt>
   0x0000000000400898 <+119>:	leave
   0x0000000000400899 <+120>:	ret
End of assembler dump.
```

That's a lot to go through, but we can see where the stack canary is loaded onto the stack at the beginning of `input_func` as well as where it's checked at the end:

```
# initialization
0x0000000000400829 <+8>:    mov    rax,QWORD PTR fs:0x28
0x0000000000400832 <+17>:	mov    QWORD PTR [rbp-0x8],rax

# tamper checking
0x0000000000400884 <+99>:	mov    rax,QWORD PTR [rbp-0x8]
0x0000000000400888 <+103>:	xor    rax,QWORD PTR fs:0x28
0x0000000000400891 <+112>:	je     0x400898 <input_func+119>
0x0000000000400893 <+114>:	call   0x400630 <__stack_chk_fail@plt>
0x0000000000400898 <+119>:	leave
0x0000000000400899 <+120>:	ret
```

Based on that, it looks like the cookie is read from the `fs` register (I'm not sure what the `0x28` means) and placed onto the stack just before the base pointer.
At the end of `input_func`, the `je` (jump if equal) instruction skips the call to `__stack_chk_fail`, but only if the stack canary hasn't changed (this is checked with the `xor` instruction).

We can also figure out where our buffer is on the stack from the above disassembly based on the setup for calling `fgets`:

```
0x000000000040085c <+59>:	mov    rdx,QWORD PTR [rip+0x20081d]        # 0x601080 <stdin@@GLIBC_2.2.5>
0x0000000000400863 <+66>:	lea    rax,[rbp-0x20]
0x0000000000400867 <+70>:	mov    esi,0xc8
0x000000000040086c <+75>:	mov    rdi,rax
0x000000000040086f <+78>:	call   0x400670 <fgets@plt>
```

The first argument to `fgets` based on its [man page](https://linux.die.net/man/3/fgets) is the buffer to write to, which in this case points to `rbp-0x20` based on the `lea` instruction.

With the location of both our buffer and the stack cookie, we can then calculate how many characters it takes to start overwriting the stack cookie by just subtracting their offsets from `rbp`: 0x20 - 0x8 = 0x18, which is 24 in decimal, so it takes 24 characters to start overwriting the stack cookie.
That's good to know, but we still need to figure out how to bypass the stack cookie itself, since our end goal is to overwrite the return address past the stack cookie with that of the `win` function.

To help with that, let's take a look at the first couple lines of output the binary gives us again:

```shell
$ ./leaking-cookies
Can you do anything with these: 0x7ffd17f6b500 0x1 0x900 0x400960 0x7fc29aee3d70 (nil) 0x7ffd17f6b648 0x7ffd17f6b530 0x14fa01f16b8b6c00 0x7ffd17f6b530 0x4008d0
Why are cookies delicious?

```

It looks like we're given a bunch of what look like addresses mixed in with other random numbers.
They also appear to change with different runs of the binary, so these aren't hardcoded values, but are instead being placed into a format string in a `printf` call above that you might have noticed:

```
0x0000000000400838 <+23>:	lea    rax,[rbp-0x20]
0x000000000040083c <+27>:	mov    rsi,rax
0x000000000040083f <+30>:	lea    rdi,[rip+0x14a]        # 0x400990
0x0000000000400846 <+37>:	mov    eax,0x0
0x000000000040084b <+42>:	call   0x400650 <printf@plt>
```

pwndbg is nice enough to give us the address from the `lea rdi,[rip+0x14a]` instruction, so we can check out the format string being fed into `printf`:

```shell
# x/s prints the first null-terminated string at the specified address
pwndbg> x/s 0x400990
0x400990:	"Can you do anything with these: %p %p %p %p %p %p %p %p %p %p %p\n"
```

Based on the [`printf` man page](https://www.man7.org/linux/man-pages/man3/printf.3.html), the `%p` format specifier prints the provided pointer argument in hexadecimal, which does match what we saw in the resulting output.
That's a lot of `%p`s, though, so `printf` ends up traversing and exhausting the arguments "provided" via registers (this is a 64-bit binary) and then the stack.
Here's the different addresses from the above output matched up with their locations in memory/registers:

- `0x7ffd17f6b500` -> `rsi` register (address of our input buffer)
- `0x1` -> `rdx` register
- `0x900` -> `rcx` register
- `0x400960` -> `r8` register
- `0x7fc29aee3d70` -> `r9` register
- `(nil)` -> top of stack/`rsp`/`rbp-0x20` (treated as a null pointer by `printf`)
- `0x7ffd17f6b648` -> `rbp-0x18` (next item in stack)
- `0x7ffd17f6b530` -> `rbp-0x10`
- `0x14fa01f16b8b6c00` -> `rbp-0x8` (location look familiar? :))
- `0x7ffd17f6b530` -> `rbp` (bottom of stack)
- `0x4008d0` -> return address in `main` (what we want to overwrite)

The register order is basically the golden standard on Unix derivatives (for C at least, Go kinda does its own thing :)), and if you're curious about it you can read a bit more about it on [Wikipedia](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI).
The `rdi` register is skipped in this case because it contains the format string, which isn't, y'know, formatted into the format string :)

I know it was a while back, but you might remember that I pointed out that the stack cookie was located at `rbp-0x8`:

```
0x0000000000400829 <+8>:    mov    rax,QWORD PTR fs:0x28
0x0000000000400832 <+17>:	mov    QWORD PTR [rbp-0x8],rax
```

So it looks like we're actually given the value of the stack cookie in that initial output!
At this point, it's just a matter of making the corresponding section of our input buffer match that value :)

You can check out my [solve script](gib_cookies.py) that does that entire process if you wish, and running it indeed gives us the flag :)

```shell
$ python gib_cookies.py
Why are cookies delicious?
you won
osu{c00k135_4r3_d3l1c10u5}
```

Cookies really are delicious :) Too bad you can't eat stack cookies though :(